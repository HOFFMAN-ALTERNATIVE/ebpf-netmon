//go:build linux && integration

package probe

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/flow"
)

// Runs only with `-tags integration` as root (CI uses sudo on a throwaway VM).
func TestLoadAttachAndCountLoopbackTraffic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root / CAP_BPF")
	}
	cg := os.Getenv("NETMON_CGROUP")
	if cg == "" {
		cg = "/sys/fs/cgroup"
	}
	p, err := Load(cg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer p.Close()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	done := make(chan int64)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- -1
			return
		}
		n, _ := io.Copy(io.Discard, c)
		c.Close()
		done <- n
	}()

	const payload = 1 << 20
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(make([]byte, payload)); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if n := <-done; n != payload {
		t.Fatalf("server read %d bytes", n)
	}

	var egress, ingress flow.Stats
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := p.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		egress, ingress = flow.Stats{}, flow.Stats{}
		for k, v := range snap {
			if k.Proto != 6 || k.Dport != port || k.Dst().String() != "127.0.0.1" {
				continue
			}
			if k.Dir == flow.Egress {
				egress.Bytes += v.Bytes
				egress.Packets += v.Packets
			} else {
				ingress.Bytes += v.Bytes
				ingress.Packets += v.Packets
			}
		}
		if egress.Bytes >= payload && ingress.Bytes >= payload {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("egress %+v ingress %+v", egress, ingress)
	if egress.Bytes < payload {
		t.Errorf("egress bytes %d < payload %d", egress.Bytes, payload)
	}
	if ingress.Bytes < payload {
		t.Errorf("ingress bytes %d < payload %d", ingress.Bytes, payload)
	}

	cnt, err := p.Counters()
	if err != nil {
		t.Fatal(err)
	}
	if cnt.Packets == 0 || cnt.ParseErrors != 0 {
		t.Errorf("unexpected probe counters %+v", cnt)
	}
}
