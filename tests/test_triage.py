"""Tests for the triage engine: known true positives vs. benign noise."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyst.enrichment import Enricher
from analyst.models import load_alerts
from analyst.triage import TriageEngine

DATA_DIR = Path(__file__).resolve().parents[1] / "sample_data"


def _results_by_id():
    engine = TriageEngine(Enricher.from_directory(DATA_DIR))
    alerts = load_alerts(DATA_DIR / "alerts.jsonl")
    return {result.alert.id: result for result in engine.triage(alerts)}


def test_brute_force_from_intel_ip_escalates():
    results = _results_by_id()
    result = results["A-001"]  # 47 failed logons from a threat-intel IP, off-hours
    assert result.disposition == "escalate", result
    assert result.score >= 70, result.score
    assert result.enrichment.intel_ip_match == "203.0.113.77"


def test_malware_with_intel_hash_is_critical():
    results = _results_by_id()
    result = results["A-009"]  # file hash on the threat-intel feed
    assert result.enrichment.intel_hash_match is True
    assert result.severity == "Critical"
    assert result.disposition == "escalate"


def test_data_exfiltration_escalates():
    results = _results_by_id()
    result = results["A-007"]  # 1.8 GiB to a threat-intel IP
    assert result.disposition == "escalate"
    assert result.score >= 85


def test_single_failed_logon_auto_closes():
    results = _results_by_id()
    result = results["A-012"]  # one wrong-password event, business hours
    assert result.disposition == "auto-close"
    assert result.score < 40


def test_scheduled_vuln_scan_auto_closes():
    results = _results_by_id()
    result = results["A-013"]  # port scan from the allow-listed scanner
    assert result.enrichment.known_scanner_source is True
    assert result.disposition == "auto-close"


def test_windows_update_download_auto_closes():
    results = _results_by_id()
    result = results["A-014"]  # large download from a known-good vendor domain
    assert result.enrichment.known_good_destination is True
    assert result.disposition == "auto-close"


def test_scores_stay_within_bounds():
    for result in _results_by_id().values():
        assert 0 <= result.score <= 100, result
