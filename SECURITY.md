# Security

## Reporting

Report vulnerabilities privately through GitHub's "Report a vulnerability" button on this repository (Security tab). I aim to reply within 72 hours. Please do not open public issues for exploitable bugs.

## Threat model

- **Assets:** host networking availability; flow metadata (who talks to whom), which is sensitive.
- **Actors:** local users reading metrics; remote scrapers; traffic generators trying to exhaust the agent.
- **Entry points:** the BPF programs (every packet), the metrics endpoint, command-line flags.
- **Top risks and mitigations:**
  - Breaking networking: both programs always return "allow"; the verifier checks them at load time; CI loads them on a real kernel on every commit.
  - Kernel memory exhaustion: fixed-size LRU map (16k flows) and a per-CPU counter array.
  - Metrics backend exhaustion: top-N and top-M limits on labelled series.
  - Leaking flow metadata: metrics bind to `127.0.0.1:9435` by default; exposing them is an explicit flag.

## Privileges

Loading and attaching needs `CAP_BPF` and `CAP_NET_ADMIN` (or root). Run the agent with exactly those capabilities, for example via systemd `AmbientCapabilities=` and a dedicated user, rather than as full root. `-demo` mode needs no privileges.
