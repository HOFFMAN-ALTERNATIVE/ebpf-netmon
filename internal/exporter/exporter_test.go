package exporter

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/flow"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/source"
)

func k(dir flow.Direction, proto uint8, src, dst string) flow.Key {
	return flow.NewKey(dir, proto, netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst))
}

func TestExportsTopFlowsAndTotals(t *testing.T) {
	f := source.NewFake()
	f.Add(k(flow.Egress, 6, "10.0.0.5:51000", "192.0.2.10:443"), 10, 9000)
	f.Add(k(flow.Ingress, 6, "198.51.100.9:60000", "10.0.0.5:22"), 4, 400)
	f.Add(k(flow.Egress, 17, "10.0.0.5:40000", "192.0.2.53:53"), 1, 80)

	c := New(f, 2, 10)
	expected := `
# HELP netmon_bytes_total All tracked bytes per direction.
# TYPE netmon_bytes_total counter
netmon_bytes_total{direction="in"} 400
netmon_bytes_total{direction="out"} 9080
# HELP netmon_flow_bytes_total Bytes for the top-N flows by volume.
# TYPE netmon_flow_bytes_total counter
netmon_flow_bytes_total{direction="in",dport="22",dst="10.0.0.5",proto="tcp",src="198.51.100.9"} 400
netmon_flow_bytes_total{direction="out",dport="443",dst="192.0.2.10",proto="tcp",src="10.0.0.5"} 9000
# HELP netmon_flows_tracked Flows currently held in the kernel LRU map.
# TYPE netmon_flows_tracked gauge
netmon_flows_tracked 3
# HELP netmon_up 1 if the last read from the probe succeeded.
# TYPE netmon_up gauge
netmon_up 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected),
		"netmon_bytes_total", "netmon_flow_bytes_total", "netmon_flows_tracked", "netmon_up"); err != nil {
		t.Fatal(err)
	}
}

func TestCardinalityIsBounded(t *testing.T) {
	f := source.NewFake()
	for i := 0; i < 500; i++ {
		f.Add(k(flow.Egress, 6, fmt.Sprintf("10.0.%d.%d:40000", i/250, i%250+1), fmt.Sprintf("192.0.2.1:%d", 1000+i)), 1, uint64(i+1))
	}
	c := New(f, 20, 15)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, mf := range mfs {
		counts[mf.GetName()] = len(mf.GetMetric())
	}
	if counts["netmon_flow_bytes_total"] != 20 {
		t.Errorf("flow series = %d, want 20", counts["netmon_flow_bytes_total"])
	}
	if counts["netmon_service_bytes_total"] != 15 {
		t.Errorf("service series = %d, want 15", counts["netmon_service_bytes_total"])
	}
}

func TestProbeFailureReportsDown(t *testing.T) {
	f := source.NewFake()
	f.Err = errors.New("map gone")
	c := New(f, 5, 5)
	expected := `
# HELP netmon_up 1 if the last read from the probe succeeded.
# TYPE netmon_up gauge
netmon_up 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "netmon_up"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c); n != 1 {
		t.Fatalf("a failed read must emit only netmon_up, got %d series", n)
	}
}

func TestLintClean(t *testing.T) {
	f := source.NewFake()
	f.Add(k(flow.Egress, 6, "10.0.0.5:51000", "192.0.2.10:443"), 1, 1)
	problems, err := testutil.CollectAndLint(New(f, 5, 5))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("metric lint problems: %+v", problems)
	}
}
