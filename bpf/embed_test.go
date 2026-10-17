package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// These tests parse the real compiled object — no privileges required — and
// pin the kernel/user-space ABI so a C change cannot silently break decoding.
func TestSpecShape(t *testing.T) {
	spec, err := Spec()
	if err != nil {
		t.Fatalf("parse object: %v", err)
	}

	flows, ok := spec.Maps["flows"]
	if !ok {
		t.Fatal("missing map 'flows'")
	}
	if flows.Type != ebpf.LRUHash {
		t.Errorf("flows type = %v, want LRUHash", flows.Type)
	}
	if flows.KeySize != 40 || flows.ValueSize != 32 {
		t.Errorf("flows key/value = %d/%d, want 40/32 (keep flow.go in sync)", flows.KeySize, flows.ValueSize)
	}
	if flows.MaxEntries != 16384 {
		t.Errorf("flows max entries = %d", flows.MaxEntries)
	}

	counters, ok := spec.Maps["counters"]
	if !ok {
		t.Fatal("missing map 'counters'")
	}
	if counters.Type != ebpf.PerCPUArray || counters.MaxEntries != 4 {
		t.Errorf("counters = %v/%d, want PerCPUArray/4", counters.Type, counters.MaxEntries)
	}

	for name, attach := range map[string]ebpf.AttachType{
		"netmon_ingress": ebpf.AttachCGroupInetIngress,
		"netmon_egress":  ebpf.AttachCGroupInetEgress,
	} {
		p, ok := spec.Programs[name]
		if !ok {
			t.Fatalf("missing program %q", name)
		}
		if p.Type != ebpf.CGroupSKB {
			t.Errorf("%s type = %v, want CGroupSKB", name, p.Type)
		}
		if p.AttachType != attach {
			t.Errorf("%s attach = %v, want %v", name, p.AttachType, attach)
		}
		if p.License != "Dual MIT/GPL" {
			t.Errorf("%s license = %q", name, p.License)
		}
	}
}
