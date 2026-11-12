"""Triage engine: weighted, rule-based scoring of enriched alerts.

Every alert starts from a base score for its type, then gains or loses points
for observable features: threat-intel hits, asset criticality, account
sensitivity, event volume, off-hours timing and known-benign sources. The
final score maps to a severity band and a disposition:

    score >= 70        -> escalate     (Critical >= 85, otherwise High)
    40 <= score < 70   -> investigate  (Medium)
    score < 40         -> auto-close   (Low)
"""

from __future__ import annotations

from .enrichment import Enricher
from .models import Alert, Enrichment, TriageResult

BASE_SCORES = {
    "malware_detected": 55,
    "privilege_escalation": 50,
    "data_exfiltration": 50,
    "c2_beacon": 45,
    "impossible_travel": 40,
    "suspicious_process": 40,
    "auth_success_after_failures": 35,
    "persistence_startup": 38,
    "brute_force": 30,
    "dns_anomaly": 30,
    "port_scan": 20,
    "failed_logon": 10,
    "large_download": 10,
    "new_device_login": 10,
    "vpn_login": 5,
    "password_reset": 5,
    "av_notice": 5,
}

CRITICALITY_POINTS = {"critical": 15, "high": 10, "medium": 5, "low": 0, "unknown": 0}

ESCALATE_THRESHOLD = 70
INVESTIGATE_THRESHOLD = 40
GIBIBYTE = 1024 ** 3
MEGABYTE = 1024 ** 2


class TriageEngine:
    def __init__(self, enricher: Enricher):
        self.enricher = enricher

    def _score(self, alert: Alert, enrichment: Enrichment) -> tuple[int, list[str]]:
        score = BASE_SCORES.get(alert.alert_type, 15)
        signals = [f"base score {score} for alert type '{alert.alert_type}'"]

        if enrichment.intel_hash_match:
            score += 30
            signals.append("file hash matches threat-intelligence feed (+30)")
        if enrichment.intel_ip_match:
            score += 25
            signals.append(f"IP {enrichment.intel_ip_match} matches threat-intelligence feed (+25)")
        if enrichment.intel_domain_match:
            score += 20
            signals.append(f"domain matches threat-intelligence entry '{enrichment.intel_domain_match}' (+20)")

        criticality_points = CRITICALITY_POINTS.get(enrichment.asset_criticality, 0)
        if criticality_points:
            score += criticality_points
            signals.append(
                f"asset criticality '{enrichment.asset_criticality}' (+{criticality_points})"
            )

        if enrichment.user_is_admin:
            score += 10
            signals.append("account holds administrative privileges (+10)")
        elif enrichment.user_sensitive_data_access:
            score += 10
            signals.append("account has access to sensitive data (+10)")
        if enrichment.user_is_service_account:
            score += 5
            signals.append("service account involved (+5)")

        hour = alert.timestamp.hour
        if hour < 6 or hour >= 22:
            score += 8
            signals.append(f"event outside business hours ({hour:02d}:00 UTC) (+8)")

        attempts = alert.details.get("failed_attempts") or alert.details.get("prior_failures") or 0
        if alert.alert_type == "brute_force":
            if attempts >= 50:
                score += 20
                signals.append(f"high failed-logon volume: {attempts} attempts (+20)")
            elif attempts >= 20:
                score += 15
                signals.append(f"elevated failed-logon volume: {attempts} attempts (+15)")
            elif attempts >= 10:
                score += 8
                signals.append(f"repeated failed logons: {attempts} attempts (+8)")

        bytes_out = alert.details.get("bytes_out") or 0
        if bytes_out >= GIBIBYTE:
            score += 20
            signals.append(f"large outbound transfer: {bytes_out / GIBIBYTE:.1f} GiB (+20)")
        elif bytes_out >= 100 * MEGABYTE:
            score += 12
            signals.append(f"elevated outbound transfer: {bytes_out / MEGABYTE:.0f} MiB (+12)")

        if alert.alert_type == "dns_anomaly" and (alert.details.get("query_count") or 0) >= 1000:
            score += 8
            signals.append(
                f"high DNS query volume to one domain: {alert.details['query_count']} queries (+8)"
            )

        if enrichment.known_scanner_source:
            score -= 40
            signals.append("source is the scheduled vulnerability scanner (-40)")
        if enrichment.known_good_destination:
            score -= 30
            signals.append("destination is a known-good vendor domain (-30)")

        return max(0, min(100, score)), signals

    @staticmethod
    def _severity_and_disposition(score: int) -> tuple[str, str]:
        if score >= 85:
            return "Critical", "escalate"
        if score >= ESCALATE_THRESHOLD:
            return "High", "escalate"
        if score >= INVESTIGATE_THRESHOLD:
            return "Medium", "investigate"
        return "Low", "auto-close"

    def triage_alert(self, alert: Alert) -> TriageResult:
        enrichment = self.enricher.enrich(alert)
        score, signals = self._score(alert, enrichment)
        severity, disposition = self._severity_and_disposition(score)
        return TriageResult(
            alert=alert,
            enrichment=enrichment,
            score=score,
            severity=severity,
            disposition=disposition,
            signals=signals,
        )

    def triage(self, alerts: list[Alert]) -> list[TriageResult]:
        results = [self.triage_alert(alert) for alert in alerts]
        results.sort(key=lambda result: result.alert.timestamp)
        return results
