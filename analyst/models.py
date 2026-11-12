"""Core data model for the autonomous cybersecurity analyst agent."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp (accepts a trailing 'Z') into an aware datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass
class Alert:
    """One normalized security alert from a SIEM / identity / endpoint source."""

    id: str
    timestamp: datetime
    alert_type: str
    source: str
    user: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    file_hash: str | None = None
    details: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict) -> "Alert":
        return cls(
            id=raw["id"],
            timestamp=parse_timestamp(raw["timestamp"]),
            alert_type=raw["alert_type"],
            source=raw.get("source", "unknown"),
            user=raw.get("user"),
            host=raw.get("host"),
            src_ip=raw.get("src_ip"),
            dst_ip=raw.get("dst_ip"),
            file_hash=raw.get("file_hash"),
            details=raw.get("details") or {},
        )


def load_alerts(path: str | Path) -> list[Alert]:
    """Load alerts from a JSON Lines file, sorted chronologically."""
    alerts: list[Alert] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            alerts.append(Alert.from_dict(raw))
    alerts.sort(key=lambda alert: alert.timestamp)
    return alerts


@dataclass
class Enrichment:
    """Context gathered about an alert from asset, user and threat-intel data."""

    asset_criticality: str = "unknown"
    asset_environment: str | None = None
    asset_owner_department: str | None = None
    user_department: str | None = None
    user_title: str | None = None
    user_is_admin: bool = False
    user_is_service_account: bool = False
    user_sensitive_data_access: bool = False
    intel_ip_match: str | None = None
    intel_hash_match: bool = False
    intel_domain_match: str | None = None
    known_good_destination: bool = False
    known_scanner_source: bool = False


@dataclass
class TriageResult:
    """Scoring outcome for one alert."""

    alert: Alert
    enrichment: Enrichment
    score: int
    severity: str
    disposition: str  # "auto-close" | "investigate" | "escalate"
    signals: list[str] = field(default_factory=list)
