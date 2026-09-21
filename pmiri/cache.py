"""Epoch- and freshness-bound decision cache."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CachedDecision:
    key: str
    value: Any
    invalidation_epoch: int
    freshness_profile_id: str
    freshness_profile_fingerprint: str


class DecisionCache:
    def __init__(self):
        self._items: dict[str, CachedDecision] = {}

    def put(self, decision: CachedDecision) -> None:
        self._items[decision.key] = decision

    def get(self, key: str, *, invalidation_epoch: int, freshness_profile_id: str, freshness_profile_fingerprint: str) -> Any | None:
        decision = self._items.get(key)
        if decision is None:
            return None
        if decision.invalidation_epoch != invalidation_epoch:
            return None
        if decision.freshness_profile_id != freshness_profile_id or decision.freshness_profile_fingerprint != freshness_profile_fingerprint:
            return None
        return decision.value

    def invalidate_epoch(self, new_epoch: int) -> None:
        self._items = {key: value for key, value in self._items.items() if value.invalidation_epoch == new_epoch}
