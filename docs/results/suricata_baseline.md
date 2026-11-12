# Rule-based baseline: Suricata with Emerging Threats Open

Generated on 2026-11-11. Suricata 8.0.8 (Docker image `jasonish/suricata`), default configuration, ET Open rules as downloaded that day, checksum validation off (`-k none`). Aggregates only.

## Real home evening, 8 November (0.99 h of traffic, 3,385 flows)

| Alert kind | Alerts | Per hour |
|---|---|---|
| capture artefact (checksum) | 99,946 | 100,956 |
| protocol anomaly | 2,826 | 2,855 |
| ruleset signature | 56 | 57 |
| **All** | **102,828** | **103,867** |

Ruleset signatures fired on 24 flows, all informational: ET INFO Session Traversal Utilities for NAT (STUN Binding Request On Non-Standard High Port) (34); ET INFO Session Traversal Utilities for NAT (STUN Binding Request) (10); ET INFO Session Traversal Utilities for NAT (STUN Binding Response) (10); ET INFO Remote Monitoring and Management (RMM) Tool in DNS Lookup (* .remotedesktop-pa .googleapis .com) (2).

## Isolated lab: three attack replicates and two all-benign service captures

| Lab scenario | Default settings: replicates with an alert | Attacker marked external: replicates with an alert | Signatures |
|---|---|---|---|
| PortScan | 0 of 3 | 0 of 3 | none |
| SSH-BruteForce | 0 of 3 | 3 of 3 | ET SCAN Potential SSH Scan |
| FTP-BruteForce | 0 of 3 | 0 of 3 | none |
| Incomplete-HTTP-Probe | 0 of 3 | 0 of 3 | none |
| SYN-Burst | 0 of 3 | 0 of 3 | none |
| BENIGN windows (false alerts) | 520 alerts | 521 alerts | ET INFO Python SimpleHTTP ServerBanner (520); ET SCAN Potential SSH Scan (1) |

Accuracy is not reported (rule 4). No addresses or per-flow records.
