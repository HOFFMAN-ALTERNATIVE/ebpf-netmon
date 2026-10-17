// Package aggregate turns cumulative kernel counters into rates and rankings.
package aggregate

import (
	"sort"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/flow"
	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/source"
)

// Rate is the per-second throughput of one flow over an interval.
type Rate struct {
	Key         flow.Key
	Bytes       uint64 // delta over the interval
	Packets     uint64
	BytesPerSec float64
	PktsPerSec  float64
	TotalBytes  uint64
}

// Delta computes per-flow deltas between two cumulative snapshots.
//
// Kernel counters are monotonic per map entry, but LRU eviction can drop a flow
// and recreate it later from zero. When a counter goes backwards we treat the
// current value as the whole delta instead of producing a huge unsigned wrap.
func Delta(prev, cur source.Snapshot, interval time.Duration) []Rate {
	secs := interval.Seconds()
	if secs <= 0 {
		secs = 1
	}
	out := make([]Rate, 0, len(cur))
	for k, c := range cur {
		p, seen := prev[k]
		db, dp := c.Bytes, c.Packets
		if seen && c.Bytes >= p.Bytes && c.Packets >= p.Packets {
			db, dp = c.Bytes-p.Bytes, c.Packets-p.Packets
		}
		if db == 0 && dp == 0 {
			continue
		}
		out = append(out, Rate{
			Key: k, Bytes: db, Packets: dp,
			BytesPerSec: float64(db) / secs, PktsPerSec: float64(dp) / secs,
			TotalBytes: c.Bytes,
		})
	}
	return out
}

// TopN returns the n busiest flows by bytes (ties broken deterministically).
func TopN(rates []Rate, n int) []Rate {
	sorted := append([]Rate(nil), rates...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Bytes != sorted[j].Bytes {
			return sorted[i].Bytes > sorted[j].Bytes
		}
		return sorted[i].Key.String() < sorted[j].Key.String()
	})
	if n >= 0 && len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

// ServiceKey groups traffic by "service" — protocol + well-known side port + direction.
type ServiceKey struct {
	Proto string
	Port  uint16
	Dir   flow.Direction
}

// ServicePort picks the server-side port: the lower of the two (ephemeral ports are high).
func ServicePort(k flow.Key) uint16 {
	if !k.HasPorts() {
		return 0
	}
	if k.Sport < k.Dport {
		return k.Sport
	}
	return k.Dport
}

// ByService sums bytes per (proto, service port, direction).
func ByService(snap source.Snapshot) map[ServiceKey]uint64 {
	out := map[ServiceKey]uint64{}
	for k, s := range snap {
		out[ServiceKey{Proto: k.ProtoName(), Port: ServicePort(k), Dir: k.Dir}] += s.Bytes
	}
	return out
}

// Totals sums bytes per direction.
func Totals(snap source.Snapshot) (in, out uint64) {
	for k, s := range snap {
		if k.Dir == flow.Ingress {
			in += s.Bytes
		} else {
			out += s.Bytes
		}
	}
	return in, out
}
