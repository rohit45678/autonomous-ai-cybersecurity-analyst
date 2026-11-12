"""Enrichment: attach asset, user and threat-intelligence context to alerts."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Alert, Enrichment


class Enricher:
    """Looks alert entities up in the asset inventory, user directory and intel feeds."""

    def __init__(self, assets: dict, users: dict, threat_intel: dict):
        self.assets = assets
        self.users = users
        self.malicious_ips = set(threat_intel.get("malicious_ips", []))
        self.malicious_hashes = set(threat_intel.get("malicious_hashes", []))
        self.malicious_domains = [d.lower() for d in threat_intel.get("malicious_domains", [])]
        self.known_good_domains = [d.lower() for d in threat_intel.get("known_good_domains", [])]
        self.scanner_ips = set(threat_intel.get("scanner_ips", []))

    @classmethod
    def from_directory(cls, directory: str | Path) -> "Enricher":
        directory = Path(directory)

        def _load(name: str) -> dict:
            with open(directory / name, "r", encoding="utf-8") as handle:
                return json.load(handle)

        return cls(
            assets=_load("assets.json"),
            users=_load("users.json"),
            threat_intel=_load("threat_intel.json"),
        )

    def _domain_match(self, domain: str | None, candidates: list[str]) -> str | None:
        if not domain:
            return None
        domain = domain.lower()
        for candidate in candidates:
            if domain == candidate or domain.endswith("." + candidate):
                return candidate
        return None

    def enrich(self, alert: Alert) -> Enrichment:
        enrichment = Enrichment()

        asset = self.assets.get(alert.host or "")
        if asset:
            enrichment.asset_criticality = asset.get("criticality", "unknown")
            enrichment.asset_environment = asset.get("environment")
            enrichment.asset_owner_department = asset.get("owner_department")

        user = self.users.get(alert.user or "")
        if user:
            enrichment.user_department = user.get("department")
            enrichment.user_title = user.get("title")
            enrichment.user_is_admin = bool(user.get("is_admin"))
            enrichment.user_is_service_account = bool(user.get("is_service_account"))
            enrichment.user_sensitive_data_access = bool(user.get("sensitive_data_access"))

        for ip in (alert.src_ip, alert.dst_ip):
            if ip and ip in self.malicious_ips:
                enrichment.intel_ip_match = ip
                break

        if alert.file_hash and alert.file_hash in self.malicious_hashes:
            enrichment.intel_hash_match = True

        domain = alert.details.get("domain")
        enrichment.intel_domain_match = self._domain_match(domain, self.malicious_domains)
        if self._domain_match(domain, self.known_good_domains):
            enrichment.known_good_destination = True

        if alert.src_ip and alert.src_ip in self.scanner_ips:
            enrichment.known_scanner_source = True

        return enrichment
