// Command netmon is an eBPF network monitor: per-flow accounting in the kernel,
// top-talkers in the terminal, and a Prometheus endpoint with bounded cardinality.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/aggregate"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/exporter"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/flow"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/probe"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/source"
)

type config struct {
	cgroup   string
	interval time.Duration
	top      int
	listen   string
	demo     bool
	quiet    bool
	ticks    int
}

func parseFlags(args []string) (config, error) {
	var c config
	fs := flag.NewFlagSet("netmon", flag.ContinueOnError)
	fs.StringVar(&c.cgroup, "cgroup", "/sys/fs/cgroup", "cgroup v2 path to monitor (root = whole host)")
	fs.DurationVar(&c.interval, "interval", 2*time.Second, "refresh interval")
	fs.IntVar(&c.top, "top", 10, "number of flows shown and exported")
	fs.StringVar(&c.listen, "listen", "127.0.0.1:9435", "Prometheus listen address (empty disables)")
	fs.BoolVar(&c.demo, "demo", false, "use synthetic traffic instead of the kernel probe (no privileges)")
	fs.BoolVar(&c.quiet, "quiet", false, "do not print the top-talkers table")
	fs.IntVar(&c.ticks, "ticks", 0, "exit after N refreshes (0 = run until signalled)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if c.interval < 100*time.Millisecond {
		return c, errors.New("interval must be >= 100ms")
	}
	if c.top < 1 || c.top > 1000 {
		return c, errors.New("top must be within 1..1000")
	}
	return c, nil
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, os.Stdout, log); err != nil {
		log.Error("netmon failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config, out io.Writer, log *slog.Logger) error {
	var src source.Source
	if cfg.demo {
		src = newDemo(ctx, cfg.interval/4)
	} else {
		p, err := probe.Load(cfg.cgroup)
		if err != nil {
			return fmt.Errorf("load probe (try -demo without privileges): %w", err)
		}
		src = p
	}
	defer src.Close()

	if cfg.listen != "" {
		reg := prometheus.NewRegistry()
		reg.MustRegister(exporter.New(src, cfg.top, 50))
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
		srv := &http.Server{Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server", "err", err)
			}
		}()
		defer srv.Close()
		log.Info("metrics listening", "addr", cfg.listen)
	}

	prev, err := src.Snapshot()
	if err != nil {
		return err
	}
	t := time.NewTicker(cfg.interval)
	defer t.Stop()
	last := time.Now()
	for n := 0; cfg.ticks == 0 || n < cfg.ticks; n++ {
		select {
		case <-ctx.Done():
			return nil
		case now := <-t.C:
			cur, err := src.Snapshot()
			if err != nil {
				return err
			}
			rates := aggregate.TopN(aggregate.Delta(prev, cur, now.Sub(last)), cfg.top)
			prev, last = cur, now
			if !cfg.quiet {
				render(out, rates, len(cur))
			}
		}
	}
	return nil
}

func render(w io.Writer, rates []aggregate.Rate, tracked int) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s  flows tracked: %d\n", time.Now().Format(time.TimeOnly), tracked)
	fmt.Fprintln(tw, "DIR\tPROTO\tSOURCE\tDESTINATION\tRATE\tPKT/s\tTOTAL")
	for _, r := range rates {
		k := r.Key
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s/s\t%.0f\t%s\n", k.Dir, k.ProtoName(),
			endpoint(k.Src(), k.Sport, k.HasPorts()), endpoint(k.Dst(), k.Dport, k.HasPorts()),
			humanBytes(r.BytesPerSec), r.PktsPerSec, humanBytes(float64(r.TotalBytes)))
	}
	fmt.Fprintln(tw)
	_ = tw.Flush()
}

func endpoint(a netip.Addr, port uint16, hasPorts bool) string {
	if !hasPorts {
		return a.String()
	}
	return netip.AddrPortFrom(a, port).String()
}

func humanBytes(b float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", b, units[i])
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}

// newDemo feeds a Fake with plausible synthetic traffic (documentation-range addresses only).
func newDemo(ctx context.Context, every time.Duration) *source.Fake {
	f := source.NewFake()
	host := netip.MustParseAddr("10.0.0.5")
	peers := []struct {
		dir   flow.Direction
		proto uint8
		peer  string
		port  uint16
		bytes uint64
	}{
		{flow.Egress, 6, "192.0.2.10", 443, 180_000},
		{flow.Ingress, 6, "198.51.100.20", 443, 900_000},
		{flow.Egress, 17, "192.0.2.53", 53, 900},
		{flow.Ingress, 6, "203.0.113.7", 22, 4_000},
		{flow.Egress, 6, "192.0.2.80", 5432, 60_000},
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for i, p := range peers {
					eph := uint16(50000 + i)
					var k flow.Key
					if p.dir == flow.Egress {
						k = flow.NewKey(p.dir, p.proto, netip.AddrPortFrom(host, eph), netip.AddrPortFrom(netip.MustParseAddr(p.peer), p.port))
					} else {
						k = flow.NewKey(p.dir, p.proto, netip.AddrPortFrom(netip.MustParseAddr(p.peer), p.port), netip.AddrPortFrom(host, eph))
					}
					b := p.bytes/2 + uint64(rand.Int64N(int64(p.bytes)))
					f.Add(k, b/1400+1, b)
				}
			}
		}
	}()
	return f
}
