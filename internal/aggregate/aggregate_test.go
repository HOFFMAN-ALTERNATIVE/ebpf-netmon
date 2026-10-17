package aggregate

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/flow"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/source"
)

func key(dir flow.Direction, proto uint8, src, dst string) flow.Key {
	return flow.NewKey(dir, proto, netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst))
}

var (
	web = key(flow.Egress, 6, "10.0.0.5:51000", "192.0.2.10:443")
	dns = key(flow.Egress, 17, "10.0.0.5:40000", "192.0.2.53:53")
	ssh = key(flow.Ingress, 6, "198.51.100.9:60000", "10.0.0.5:22")
)

func TestDeltaComputesRates(t *testing.T) {
	prev := source.Snapshot{web: {Packets: 10, Bytes: 10_000}}
	cur := source.Snapshot{web: {Packets: 30, Bytes: 30_000}, dns: {Packets: 2, Bytes: 200}}
	rates := Delta(prev, cur, 2*time.Second)
	if len(rates) != 2 {
		t.Fatalf("want 2 rates, got %d", len(rates))
	}
	byKey := map[flow.Key]Rate{}
	for _, r := range rates {
		byKey[r.Key] = r
	}
	if r := byKey[web]; r.Bytes != 20_000 || r.BytesPerSec != 10_000 || r.PktsPerSec != 10 {
		t.Errorf("web rate wrong: %+v", r)
	}
	if r := byKey[dns]; r.Bytes != 200 || r.TotalBytes != 200 {
		t.Errorf("new flow must count fully: %+v", r)
	}
}

func TestDeltaSkipsIdleFlows(t *testing.T) {
	s := source.Snapshot{web: {Packets: 5, Bytes: 500}}
	if got := Delta(s, s, time.Second); len(got) != 0 {
		t.Fatalf("idle flow reported: %+v", got)
	}
}

func TestDeltaHandlesLRUEvictionReset(t *testing.T) {
	prev := source.Snapshot{web: {Packets: 1000, Bytes: 1_000_000}}
	cur := source.Snapshot{web: {Packets: 3, Bytes: 300}} // evicted + recreated
	r := Delta(prev, cur, time.Second)
	if len(r) != 1 || r[0].Bytes != 300 {
		t.Fatalf("reset must not wrap around: %+v", r)
	}
}

func TestDeltaGuardsZeroInterval(t *testing.T) {
	r := Delta(nil, source.Snapshot{web: {Packets: 1, Bytes: 100}}, 0)
	if r[0].BytesPerSec != 100 {
		t.Fatalf("zero interval must not divide by zero: %+v", r[0])
	}
}

func TestTopNOrdersAndTruncates(t *testing.T) {
	rates := []Rate{{Key: dns, Bytes: 10}, {Key: web, Bytes: 500}, {Key: ssh, Bytes: 90}}
	top := TopN(rates, 2)
	if len(top) != 2 || top[0].Key != web || top[1].Key != ssh {
		t.Fatalf("unexpected order: %+v", top)
	}
	if len(rates) != 3 || rates[0].Key != dns {
		t.Fatal("TopN must not mutate its input")
	}
	if len(TopN(rates, -1)) != 3 {
		t.Fatal("negative n means unlimited")
	}
}

func TestTopNIsDeterministicOnTies(t *testing.T) {
	a := TopN([]Rate{{Key: web, Bytes: 1}, {Key: dns, Bytes: 1}}, 2)
	b := TopN([]Rate{{Key: dns, Bytes: 1}, {Key: web, Bytes: 1}}, 2)
	if a[0].Key != b[0].Key {
		t.Fatal("tie-break must be stable regardless of input order")
	}
}

func TestServicePortPicksServerSide(t *testing.T) {
	if p := ServicePort(web); p != 443 {
		t.Errorf("egress https: got %d", p)
	}
	if p := ServicePort(ssh); p != 22 {
		t.Errorf("ingress ssh: got %d", p)
	}
	icmp := key(flow.Ingress, 1, "192.0.2.1:0", "192.0.2.2:0")
	if p := ServicePort(icmp); p != 0 {
		t.Errorf("icmp: got %d", p)
	}
}

func TestByServiceAndTotals(t *testing.T) {
	web2 := key(flow.Egress, 6, "10.0.0.5:51001", "192.0.2.11:443")
	snap := source.Snapshot{web: {Bytes: 100}, web2: {Bytes: 50}, dns: {Bytes: 7}, ssh: {Bytes: 1000}}
	svc := ByService(snap)
	if got := svc[ServiceKey{"tcp", 443, flow.Egress}]; got != 150 {
		t.Errorf("https egress = %d, want 150", got)
	}
	if got := svc[ServiceKey{"udp", 53, flow.Egress}]; got != 7 {
		t.Errorf("dns = %d", got)
	}
	in, out := Totals(snap)
	if in != 1000 || out != 157 {
		t.Errorf("totals in=%d out=%d", in, out)
	}
}

func TestFakeSourceEviction(t *testing.T) {
	f := source.NewFake()
	f.Add(web, 1, 100)
	f.Add(web, 1, 100)
	f.Evict(web)
	f.Add(web, 1, 40)
	s, _ := f.Snapshot()
	if s[web].Bytes != 40 {
		t.Fatalf("fake must restart counters after eviction: %+v", s[web])
	}
	c, _ := f.Counters()
	if c.Packets != 3 {
		t.Fatalf("counters.Packets = %d", c.Packets)
	}
}
