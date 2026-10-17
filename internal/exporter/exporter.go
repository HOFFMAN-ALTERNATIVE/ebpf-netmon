// Package exporter exposes flow data as Prometheus metrics with bounded cardinality.
package exporter

import (
	"sort"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/aggregate"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/source"
)

// Collector reads a Source on every scrape (no background goroutine, no stale data).
type Collector struct {
	src         source.Source
	topN        int
	maxServices int

	flowBytes    *prometheus.Desc
	flowPackets  *prometheus.Desc
	serviceBytes *prometheus.Desc
	dirBytes     *prometheus.Desc
	tracked      *prometheus.Desc
	probe        *prometheus.Desc
	up           *prometheus.Desc
}

// New builds a Collector. topN bounds per-flow series; maxServices bounds per-port series.
func New(src source.Source, topN, maxServices int) *Collector {
	flowLabels := []string{"direction", "proto", "src", "dst", "dport"}
	return &Collector{
		src: src, topN: topN, maxServices: maxServices,
		flowBytes:    prometheus.NewDesc("netmon_flow_bytes_total", "Bytes for the top-N flows by volume.", flowLabels, nil),
		flowPackets:  prometheus.NewDesc("netmon_flow_packets_total", "Packets for the top-N flows by volume.", flowLabels, nil),
		serviceBytes: prometheus.NewDesc("netmon_service_bytes_total", "Bytes per protocol / service port / direction.", []string{"direction", "proto", "port"}, nil),
		dirBytes:     prometheus.NewDesc("netmon_bytes_total", "All tracked bytes per direction.", []string{"direction"}, nil),
		tracked:      prometheus.NewDesc("netmon_flows_tracked", "Flows currently held in the kernel LRU map.", nil, nil),
		probe:        prometheus.NewDesc("netmon_probe_events_total", "Probe health counters.", []string{"event"}, nil),
		up:           prometheus.NewDesc("netmon_up", "1 if the last read from the probe succeeded.", nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.flowBytes, c.flowPackets, c.serviceBytes, c.dirBytes, c.tracked, c.probe, c.up} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	snap, err := c.src.Snapshot()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.tracked, prometheus.GaugeValue, float64(len(snap)))

	in, out := aggregate.Totals(snap)
	ch <- prometheus.MustNewConstMetric(c.dirBytes, prometheus.CounterValue, float64(in), "in")
	ch <- prometheus.MustNewConstMetric(c.dirBytes, prometheus.CounterValue, float64(out), "out")

	// cumulative totals ranked: treat the whole snapshot as one interval from zero
	for _, r := range aggregate.TopN(aggregate.Delta(nil, snap, 1), c.topN) {
		k := r.Key
		labels := []string{k.Dir.String(), k.ProtoName(), k.Src().String(), k.Dst().String(), strconv.Itoa(int(k.Dport))}
		ch <- prometheus.MustNewConstMetric(c.flowBytes, prometheus.CounterValue, float64(r.TotalBytes), labels...)
		ch <- prometheus.MustNewConstMetric(c.flowPackets, prometheus.CounterValue, float64(snap[k].Packets), labels...)
	}

	type svc struct {
		k aggregate.ServiceKey
		b uint64
	}
	var svcs []svc
	for k, b := range aggregate.ByService(snap) {
		svcs = append(svcs, svc{k, b})
	}
	sort.Slice(svcs, func(i, j int) bool {
		if svcs[i].b != svcs[j].b {
			return svcs[i].b > svcs[j].b
		}
		return svcs[i].k.Port < svcs[j].k.Port
	})
	if len(svcs) > c.maxServices {
		svcs = svcs[:c.maxServices]
	}
	for _, s := range svcs {
		ch <- prometheus.MustNewConstMetric(c.serviceBytes, prometheus.CounterValue, float64(s.b),
			s.k.Dir.String(), s.k.Proto, strconv.Itoa(int(s.k.Port)))
	}

	if cnt, err := c.src.Counters(); err == nil {
		for name, v := range map[string]uint64{
			"packets": cnt.Packets, "unsupported": cnt.Unsupported,
			"parse_error": cnt.ParseErrors, "update_error": cnt.UpdateErrors,
		} {
			ch <- prometheus.MustNewConstMetric(c.probe, prometheus.CounterValue, float64(v), name)
		}
	}
}
