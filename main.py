#!/usr/bin/env python3
"""CLI entry point for the autonomous AI cybersecurity analyst agent.

Usage:
    python main.py [--alerts sample_data/alerts.jsonl] [--data-dir sample_data] [--out out]

Loads alerts, enriches them with asset/user/threat-intel context, scores and
dispositions each one, correlates the actionable alerts into incident
clusters, writes one Markdown incident report per cluster, and prints a
triage table plus the clusters found.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyst.enrichment import Enricher
from analyst.investigation import correlate
from analyst.models import load_alerts
from analyst.report import write_reports
from analyst.triage import TriageEngine


def print_triage_table(results) -> None:
    header = f"{'ID':<7} {'Time (UTC)':<18} {'Type':<27} {'User':<9} {'Host':<11} {'Score':>5}  {'Severity':<9} Disposition"
    print(header)
    print("-" * len(header))
    for result in results:
        alert = result.alert
        print(
            f"{alert.id:<7} {alert.timestamp.strftime('%m-%d %H:%M:%S'):<18} "
            f"{alert.alert_type:<27} {(alert.user or '-'):<9} {(alert.host or '-'):<11} "
            f"{result.score:>5}  {result.severity:<9} {result.disposition}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Autonomous AI cybersecurity analyst agent")
    parser.add_argument("--alerts", default="sample_data/alerts.jsonl", help="Path to alerts JSONL file")
    parser.add_argument("--data-dir", default="sample_data", help="Directory with assets/users/threat-intel fixtures")
    parser.add_argument("--out", default="out", help="Directory for generated incident reports")
    args = parser.parse_args(argv)

    alerts = load_alerts(args.alerts)
    enricher = Enricher.from_directory(args.data_dir)
    engine = TriageEngine(enricher)
    results = engine.triage(alerts)

    print(f"Loaded {len(alerts)} alerts from {args.alerts}\n")
    print("== Triage ==")
    print_triage_table(results)

    counts = {"auto-close": 0, "investigate": 0, "escalate": 0}
    for result in results:
        counts[result.disposition] += 1
    print(
        f"\nDispositions: {counts['escalate']} escalate, "
        f"{counts['investigate']} investigate, {counts['auto-close']} auto-close"
    )

    clusters = correlate(results)
    print(f"\n== Incident clusters ({len(clusters)}) ==")
    for cluster in clusters:
        member_ids = ", ".join(member.alert.id for member in cluster.members)
        print(
            f"{cluster.id}: severity={cluster.severity} alerts=[{member_ids}] "
            f"users={cluster.users} hosts={cluster.hosts}"
        )

    written = write_reports(clusters, args.out)
    if written:
        print(f"\nWrote {len(written)} incident report(s) to {args.out}/:")
        for path in written:
            print(f"  - {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
