# 0003. Bounded Prometheus cardinality
Status: accepted
Date: 2026-10-17

## Context
Exporting one time series per flow would let a port scan or a busy NAT gateway create millions of series and take down the Prometheus server that is supposed to monitor the incident.

## Options
1. One series per flow. Maximum detail. Unbounded cardinality.
2. Only aggregated totals. Safe, but answers no "who is talking" question.
3. Top-N flows and top-M services as labelled series, everything else folded into totals.

## Decision
Option 3. It keeps the useful answer (the biggest talkers) with a hard ceiling on series count.

## Consequences
- Small flows are only visible in totals and in the terminal view.
- The ceiling is enforced in the exporter and covered by tests (`testutil.CollectAndCompare` and cardinality caps).
- Probe health (`netmon_up`, `netmon_probe_events_total`) is exported separately so a broken probe is visible.
