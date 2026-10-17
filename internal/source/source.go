// Package source abstracts where flow snapshots come from: the live eBPF probe
// in production, or an in-memory fake in tests and demos.
package source

import (
	"sync"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/flow"
)

// Snapshot is a point-in-time copy of all tracked flows.
type Snapshot map[flow.Key]flow.Stats

// Counters are the probe's health counters (summed over CPUs).
type Counters struct {
	Packets      uint64
	Unsupported  uint64
	ParseErrors  uint64
	UpdateErrors uint64
}

// Source yields snapshots of cumulative per-flow counters.
type Source interface {
	Snapshot() (Snapshot, error)
	Counters() (Counters, error)
	Close() error
}

// Fake is a concurrency-safe in-memory Source.
type Fake struct {
	mu       sync.Mutex
	flows    Snapshot
	counters Counters
	Err      error
}

// NewFake returns an empty Fake.
func NewFake() *Fake { return &Fake{flows: Snapshot{}} }

// Add accounts packets/bytes for a flow the same way the kernel program does.
func (f *Fake) Add(k flow.Key, packets, bytes uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.flows[k]
	s.Packets += packets
	s.Bytes += bytes
	f.flows[k] = s
	f.counters.Packets += packets
}

// Evict drops a flow, mimicking LRU eviction in the kernel map.
func (f *Fake) Evict(k flow.Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.flows, k)
}

// Snapshot implements Source.
func (f *Fake) Snapshot() (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	out := make(Snapshot, len(f.flows))
	for k, v := range f.flows {
		out[k] = v
	}
	return out, nil
}

// Counters implements Source.
func (f *Fake) Counters() (Counters, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counters, f.Err
}

// Close implements Source.
func (f *Fake) Close() error { return nil }
