"""Bounded local distributed-ingestion primitives."""
from __future__ import annotations
from collections import deque
from datetime import datetime, timezone
import threading

class EventBuffer:
    def __init__(self, max_events: int = 50000):
        self._items = deque(maxlen=max_events)
        self._lock = threading.Lock()
    def add(self, event):
        with self._lock:
            self._items.append(event)
    def snapshot(self):
        with self._lock:
            return list(self._items)

def utc_now() -> datetime:
    return datetime.now(timezone.utc)
