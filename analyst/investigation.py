"""Investigation: correlate triaged alerts into incident clusters.

Alerts that were not auto-closed are linked into a graph when they share a
user or a host and occur within a correlation window of each other. The
connected components of that graph are the incident clusters: each one is a
candidate incident with its own timeline, blast radius and severity (the
maximum severity among its member alerts).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from .models import TriageResult

SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
DEFAULT_WINDOW = timedelta(hours=4)


@dataclass
class IncidentCluster:
    id: str
    members: list[TriageResult] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return max((m.severity for m in self.members), key=lambda s: SEVERITY_RANK[s])

    @property
    def max_score(self) -> int:
        return max(m.score for m in self.members)

    @property
    def users(self) -> list[str]:
        return sorted({m.alert.user for m in self.members if m.alert.user})

    @property
    def hosts(self) -> list[str]:
        return sorted({m.alert.host for m in self.members if m.alert.host})

    @property
    def start(self):
        return min(m.alert.timestamp for m in self.members)

    @property
    def end(self):
        return max(m.alert.timestamp for m in self.members)

    @property
    def alert_types(self) -> list[str]:
        return sorted({m.alert.alert_type for m in self.members})


class _UnionFind:
    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self.parent[root_b] = root_a


def _shares_entity(a: TriageResult, b: TriageResult) -> str | None:
    if a.alert.user and a.alert.user == b.alert.user:
        return f"user '{a.alert.user}'"
    if a.alert.host and a.alert.host == b.alert.host:
        return f"host '{a.alert.host}'"
    return None


def correlate(
    results: list[TriageResult],
    window: timedelta = DEFAULT_WINDOW,
    min_members: int = 1,
) -> list[IncidentCluster]:
    """Group actionable (non auto-closed) results into incident clusters."""
    actionable = [r for r in results if r.disposition != "auto-close"]
    actionable.sort(key=lambda r: r.alert.timestamp)

    union_find = _UnionFind(len(actionable))
    for i in range(len(actionable)):
        for j in range(i + 1, len(actionable)):
            delta = actionable[j].alert.timestamp - actionable[i].alert.timestamp
            if delta > window:
                break  # sorted by time: later alerts are only further away
            if _shares_entity(actionable[i], actionable[j]):
                union_find.union(i, j)

    groups: dict[int, list[TriageResult]] = {}
    for index, result in enumerate(actionable):
        groups.setdefault(union_find.find(index), []).append(result)

    clusters: list[IncidentCluster] = []
    ordered = sorted(groups.values(), key=lambda members: members[0].alert.timestamp)
    for number, members in enumerate(ordered, start=1):
        if len(members) < min_members:
            continue
        clusters.append(
            IncidentCluster(id=f"INC-{number:03d}", members=sorted(members, key=lambda r: r.alert.timestamp))
        )
    return clusters
