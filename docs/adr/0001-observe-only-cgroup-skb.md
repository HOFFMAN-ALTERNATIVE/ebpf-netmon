# 0001. Observe-only cgroup_skb hooks
Status: accepted
Date: 2026-10-17

## Context
The tool must see per-flow traffic on production hosts. Whatever hook it uses runs on every packet, and a bug in a monitoring tool must never take networking down.

## Options
1. XDP. Fastest and earliest hook. Ingress only, per-interface attachment, and the program decides whether a packet passes.
2. TC (clsact) ingress/egress. Sees forwarded traffic too. Per-interface; the return code can drop or redirect packets.
3. `cgroup_skb` ingress/egress on a cgroup v2 hierarchy. One attach point covers every socket in the subtree, works per service (systemd slice, container cgroup), and the program can be written to always return "allow".

## Decision
Option 3 with both programs hard-wired to return `1`. Per-service scoping comes for free, and the program cannot drop traffic even if its parsing is wrong.

## Consequences
- Only traffic of local sockets is visible; forwarded or bridged traffic needs a TC hook later.
- Requires cgroup v2 and Linux 5.8+.
- Parsing errors are counted (`parse_error`) instead of affecting packets.
