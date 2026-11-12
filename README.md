# Autonomous AI Cybersecurity Analyst
AI agent that analyzes security alerts, investigates suspicious activity against the MITRE ATT&CK framework, and generates structured incident reports for analyst review.
**Tech stack:** Python, LangGraph, Llama, MITRE ATT&CK
**Highlights:** automated alert triage; ATT&CK-mapped investigations; incident report generation.

## What it does

A working, end-to-end implementation of the agent's core pipeline in pure
Python 3.12 (standard library only — no API keys or external services needed
to run it). Given a day of SIEM / identity / endpoint alerts, the agent:

1. **Enriches** every alert with asset criticality, user context (department,
   admin rights, sensitive-data access) and threat-intelligence lookups
   (malicious IPs, file hashes, domains; known-good destinations and scanner
   allow-lists).
2. **Triages** each alert with a weighted, rule-based scoring engine
   (0–100). Intel hits, critical assets, privileged accounts, event volume
   (failed-logon counts, exfiltration size, DNS query volume) and off-hours
   timing raise the score; known-benign sources lower it. Scores map to a
   severity and a disposition: `escalate` (≥ 70), `investigate` (40–69) or
   `auto-close` (< 40). Every point is explained by a named scoring signal,
   so an analyst can audit exactly why each alert scored the way it did.
3. **Investigates** by correlating actionable alerts that share a user or a
   host within a 4-hour window into incident clusters (connected components),
   turning isolated alerts into attack narratives — e.g. brute force →
   successful logon → privilege escalation → encoded PowerShell.
4. **Reports** one Markdown incident report per cluster with a timeline,
   per-alert evidence and scoring signals, a MITRE ATT&CK mapping and
   concrete recommended actions.

The scoring engine is the deterministic core a LangGraph/Llama layer can sit
on top of: an LLM node would consume the same `TriageResult` objects (score,
signals, enrichment) to draft narratives, while dispositions stay
reproducible and testable.

## Sample data

`sample_data/` contains one day of realistic fixtures (18 alerts): three true
incidents — a credential attack with privilege escalation (`jsmith`), an
impossible-travel session followed by a 1.7 GiB exfiltration and DNS
tunneling (`mpatel`), and a malware infection with C2 beaconing and startup
persistence (`agarcia`) — mixed with benign noise the agent must auto-close:
a scheduled Nessus scan, a Windows Update download, a single typo'd password,
a help-desk password reset, a compliant new-device logon and an on-call
admin's after-hours VPN session.

## Architecture

```
main.py                  CLI entry point
analyst/
  models.py              Alert / Enrichment / TriageResult dataclasses, JSONL loader
  enrichment.py          Asset, user-directory and threat-intel lookups
  triage.py              Weighted scoring engine, severity + disposition bands
  investigation.py       Union-find correlation of alerts into incident clusters
  report.py              Markdown incident reports, ATT&CK mapping, playbook actions
sample_data/
  alerts.jsonl           Alert fixtures (input)
  assets.json            Host inventory with criticality
  users.json             User directory with roles and risk flags
  threat_intel.json      Malicious IPs / hashes / domains, known-good lists
tests/                   Triage and clustering tests (pytest-compatible)
out/                     Generated incident reports (git-ignored)
```

## How to run

```bash
python main.py --alerts sample_data/alerts.jsonl
```

This prints the triage table, the incident clusters found, and writes reports
to `out/`. Use `--data-dir` to point at different enrichment fixtures and
`--out` to change the report directory.

## Sample output

```
Dispositions: 7 escalate, 3 investigate, 8 auto-close

== Incident clusters (3) ==
INC-001: severity=High alerts=[A-001, A-002, A-003, A-004] users=['jsmith'] hosts=['WS-1042']
INC-002: severity=Critical alerts=[A-006, A-007, A-008] users=['mpatel'] hosts=['FILE-SRV-02', 'WS-2210']
INC-003: severity=Critical alerts=[A-009, A-010, A-011] users=['agarcia'] hosts=['WS-0877']

Wrote 3 incident report(s) to out/:
  - out/inc-001-report.md
  - out/inc-002-report.md
  - out/inc-003-report.md
```

## Tests

```bash
python tests/run_tests.py     # dependency-free runner
pytest tests/                 # also works if pytest is installed
```

The suite covers scoring of known true positives (brute force from an intel
IP, intel-hash malware hit, bulk exfiltration), correct auto-close of benign
noise (scanner, OS update, single failed logon), and the clustering of each
attack chain into a single incident.
