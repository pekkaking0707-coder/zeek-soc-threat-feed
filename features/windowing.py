"""Time-windowed accumulation of per-key events (flows, DNS queries).

The streaming backbone for constraint (c): events are appended as they arrive;
features are computed over the last `window_s` only — no batch passes.
"""

from __future__ import annotations

from collections import defaultdict, deque


class SlidingWindow:
    def __init__(self, window_s: float):
        self.window_s = window_s
        self._buckets: dict[str, deque[tuple[float, dict]]] = defaultdict(deque)

    def add(self, key: str, ts: float, event: dict) -> None:
        dq = self._buckets[key]
        dq.append((ts, event))
        self.evict(key, ts)

    def evict(self, key: str, now_ts: float) -> None:
        dq = self._buckets[key]
        cutoff = now_ts - self.window_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def snapshot(self, key: str) -> list[dict]:
        return [event for _, event in self._buckets.get(key, deque())]

    def keys(self) -> list[str]:
        return list(self._buckets.keys())
