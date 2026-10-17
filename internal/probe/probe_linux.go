//go:build linux

// Package probe loads the netmon eBPF programs and attaches them to a cgroup v2 hierarchy.
package probe

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/bpf"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/flow"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/source"
)

// Probe is a live, kernel-backed source.Source.
type Probe struct {
	coll  *ebpf.Collection
	links []link.Link
}

var _ source.Source = (*Probe)(nil)

// Load verifies and loads the programs, then attaches ingress + egress hooks to cgroupPath
// (e.g. /sys/fs/cgroup for the whole host). Requires CAP_BPF + CAP_NET_ADMIN (or root).
func Load(cgroupPath string) (p *Probe, err error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	spec, err := bpf.Spec()
	if err != nil {
		return nil, fmt.Errorf("parse bpf object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected program: %+v", ve)
		}
		return nil, fmt.Errorf("load collection: %w", err)
	}
	p = &Probe{coll: coll}
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	for _, h := range []struct {
		prog   string
		attach ebpf.AttachType
	}{
		{"netmon_ingress", ebpf.AttachCGroupInetIngress},
		{"netmon_egress", ebpf.AttachCGroupInetEgress},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: h.attach, Program: coll.Programs[h.prog]})
		if err != nil {
			return nil, fmt.Errorf("attach %s to %s: %w", h.prog, cgroupPath, err)
		}
		p.links = append(p.links, l)
	}
	return p, nil
}

// Snapshot copies every flow out of the kernel LRU map.
func (p *Probe) Snapshot() (source.Snapshot, error) {
	out := source.Snapshot{}
	var (
		k flow.Key
		v flow.Stats
	)
	it := p.coll.Maps["flows"].Iterate()
	for it.Next(&k, &v) {
		out[k] = v
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate flows: %w", err)
	}
	return out, nil
}

// Counters sums the per-CPU health counters.
func (p *Probe) Counters() (source.Counters, error) {
	var c source.Counters
	dst := []*uint64{&c.Packets, &c.Unsupported, &c.ParseErrors, &c.UpdateErrors}
	for i := range dst {
		var perCPU []uint64
		if err := p.coll.Maps["counters"].Lookup(uint32(i), &perCPU); err != nil {
			return c, fmt.Errorf("lookup counter %d: %w", i, err)
		}
		for _, v := range perCPU {
			*dst[i] += v
		}
	}
	return c, nil
}

// Close detaches the hooks and releases kernel objects.
func (p *Probe) Close() error {
	var errs []error
	for _, l := range p.links {
		errs = append(errs, l.Close())
	}
	p.links = nil
	if p.coll != nil {
		p.coll.Close()
		p.coll = nil
	}
	return errors.Join(errs...)
}
