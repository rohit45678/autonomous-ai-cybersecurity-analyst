"""Tests for alert correlation into incident clusters."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyst.enrichment import Enricher
from analyst.investigation import correlate
from analyst.models import load_alerts
from analyst.triage import TriageEngine

DATA_DIR = Path(__file__).resolve().parents[1] / "sample_data"


def _clusters():
    engine = TriageEngine(Enricher.from_directory(DATA_DIR))
    results = engine.triage(load_alerts(DATA_DIR / "alerts.jsonl"))
    return correlate(results)


def _cluster_containing(clusters, alert_id):
    for cluster in clusters:
        if any(member.alert.id == alert_id for member in cluster.members):
            return cluster
    return None


def test_three_incidents_found():
    clusters = _clusters()
    assert len(clusters) == 3, [c.id for c in clusters]


def test_account_takeover_chain_clusters_together():
    cluster = _cluster_containing(_clusters(), "A-001")
    assert cluster is not None
    member_ids = {member.alert.id for member in cluster.members}
    # brute force -> success -> privilege escalation -> encoded PowerShell
    assert member_ids == {"A-001", "A-002", "A-003", "A-004"}, member_ids
    assert cluster.users == ["jsmith"]
    assert cluster.severity in ("High", "Critical")


def test_impossible_travel_and_exfiltration_cluster_together():
    cluster = _cluster_containing(_clusters(), "A-007")
    assert cluster is not None
    member_ids = {member.alert.id for member in cluster.members}
    assert member_ids == {"A-006", "A-007", "A-008"}, member_ids
    assert cluster.users == ["mpatel"]


def test_malware_cluster_groups_host_activity():
    cluster = _cluster_containing(_clusters(), "A-009")
    assert cluster is not None
    member_ids = {member.alert.id for member in cluster.members}
    assert member_ids == {"A-009", "A-010", "A-011"}, member_ids
    assert cluster.hosts == ["WS-0877"]
    assert cluster.severity == "Critical"


def test_benign_alerts_form_no_cluster():
    clusters = _clusters()
    for benign_id in ("A-012", "A-013", "A-014", "A-015", "A-016", "A-017", "A-018"):
        assert _cluster_containing(clusters, benign_id) is None, benign_id


def test_clusters_are_chronological():
    for cluster in _clusters():
        timestamps = [member.alert.timestamp for member in cluster.members]
        assert timestamps == sorted(timestamps)
