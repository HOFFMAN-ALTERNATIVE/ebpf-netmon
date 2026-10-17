# 0002. In-kernel LRU aggregation instead of per-packet events
Status: accepted
Date: 2026-10-17

## Context
The agent needs packets and bytes per flow. It could receive one event per packet (perf or ring buffer) and aggregate in Go, or let the kernel aggregate and read counters periodically.

## Options
1. Ring buffer with one event per packet. Full fidelity, easy to extend. Cost grows with packet rate; under load events are dropped or the agent burns CPU.
2. `LRU_HASH` map keyed by 5-tuple and direction, updated with atomic adds; the agent iterates it every interval. Cost in user space is proportional to the number of flows, not packets.

## Decision
Option 2. Monitoring cost must not scale with traffic volume.

## Consequences
- The map is fixed at 16k entries; under more concurrent flows the LRU evicts the oldest. The aggregator detects counter resets so evicted-and-recreated flows do not produce wrapped rates.
- Per-packet detail (sizes, timing) is not available; only counters and first/last seen.
- Inserts use `BPF_NOEXIST` with a fallback for the race where two CPUs create the same flow.
