"""
In-memory usage statistics collector.

Accumulates operation counts during a session and flushes to disk on close.
"""

import os
from datetime import date, datetime


def _stats_enabled():
    """Check if stats collection is enabled.

    Stats are only collected when DEV_EDITION_* env vars are set (i.e. Developer Edition).
    Can be explicitly overridden with PTY_STATS=true/false.
    """
    explicit = os.getenv("PTY_STATS")
    if explicit is not None:
        return explicit.lower() not in ("false", "0", "no", "off")
    # Default: enabled only when Developer Edition env vars are present
    return any(k.startswith("DEV_EDITION_") for k in os.environ)


class UsageCollector:
    """Collects usage statistics in memory during a session.

    Stats are accumulated per data element and policy user, then flushed
    to disk when flush() is called (typically on session close).
    """

    def __init__(self, user):
        self._enabled = _stats_enabled()
        self._user = user
        self._data_elements = {}
        self._session_started = date.today().isoformat()

    @property
    def enabled(self):
        return self._enabled

    def record_protect(self, data_element):
        """Record a protect operation for a data element."""
        if not self._enabled:
            return
        self._ensure_element(data_element)
        self._data_elements[data_element]["protect_count"] += 1
        self._data_elements[data_element]["last_used"] = date.today().isoformat()

    def record_unprotect(self, data_element):
        """Record an unprotect operation for a data element."""
        if not self._enabled:
            return
        self._ensure_element(data_element)
        self._data_elements[data_element]["unprotect_count"] += 1
        self._data_elements[data_element]["last_used"] = date.today().isoformat()

    def record_reprotect(self, source_de, target_de):
        """Record a reprotect operation for source and target data elements."""
        if not self._enabled:
            return
        self._ensure_element(source_de)
        self._ensure_element(target_de)
        self._data_elements[source_de]["reprotect_source_count"] += 1
        self._data_elements[source_de]["last_used"] = date.today().isoformat()
        self._data_elements[target_de]["reprotect_target_count"] += 1
        self._data_elements[target_de]["last_used"] = date.today().isoformat()

    def get_session_data(self):
        """Return collected stats for this session.

        Returns:
            dict: Session stats with user, data_elements, and metadata.
        """
        return {
            "user": self._user,
            "data_elements": dict(self._data_elements),
        }

    def _ensure_element(self, data_element):
        """Ensure a data element entry exists in the collection."""
        if data_element not in self._data_elements:
            today = date.today().isoformat()
            self._data_elements[data_element] = {
                "protect_count": 0,
                "unprotect_count": 0,
                "reprotect_source_count": 0,
                "reprotect_target_count": 0,
                "first_used": today,
                "last_used": today,
            }
