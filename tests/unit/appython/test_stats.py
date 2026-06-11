"""Unit tests for UsageCollector and StatsWriter (PTY-151136)."""

import json
import os
import tempfile
from datetime import date
from unittest.mock import patch

import pytest

from appython.stats.collector import UsageCollector, _stats_enabled
from appython.stats.writer import flush_stats, _stats_path, _empty_stats, _merge_session, _read_stats

pytestmark = pytest.mark.migration


# ──────────────────────────────────────────────────────────────
# _stats_enabled() — opt-in/opt-out logic
# ──────────────────────────────────────────────────────────────

class TestStatsEnabled:

    def test_enabled_when_dev_edition_vars_present(self):
        with patch.dict(os.environ, {"DEV_EDITION_EMAIL": "x@y.com"}, clear=False):
            assert _stats_enabled() is True

    def test_disabled_when_no_dev_edition_vars(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DEV_EDITION_")}
        with patch.dict(os.environ, env, clear=True):
            # Remove PTY_STATS if present
            os.environ.pop("PTY_STATS", None)
            assert _stats_enabled() is False

    def test_explicit_override_true(self):
        env = {"PTY_STATS": "true"}
        with patch.dict(os.environ, env, clear=True):
            assert _stats_enabled() is True

    def test_explicit_override_false(self):
        with patch.dict(os.environ, {"PTY_STATS": "false", "DEV_EDITION_EMAIL": "x"}, clear=False):
            assert _stats_enabled() is False

    def test_explicit_override_off(self):
        with patch.dict(os.environ, {"PTY_STATS": "off", "DEV_EDITION_EMAIL": "x"}, clear=False):
            assert _stats_enabled() is False


# ──────────────────────────────────────────────────────────────
# UsageCollector — accumulation
# ──────────────────────────────────────────────────────────────

class TestUsageCollector:

    @pytest.fixture
    def collector(self):
        with patch.dict(os.environ, {"DEV_EDITION_EMAIL": "user@test.com"}, clear=False):
            return UsageCollector(user="testuser")

    @pytest.fixture
    def disabled_collector(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DEV_EDITION_")}
        with patch.dict(os.environ, env, clear=True):
            os.environ.pop("PTY_STATS", None)
            return UsageCollector(user="testuser")

    def test_enabled_property(self, collector):
        assert collector.enabled is True

    def test_disabled_property(self, disabled_collector):
        assert disabled_collector.enabled is False

    def test_record_protect(self, collector):
        collector.record_protect("SSN")
        data = collector.get_session_data()
        assert data["data_elements"]["SSN"]["protect_count"] == 1
        assert data["data_elements"]["SSN"]["unprotect_count"] == 0

    def test_record_unprotect(self, collector):
        collector.record_unprotect("CC")
        data = collector.get_session_data()
        assert data["data_elements"]["CC"]["unprotect_count"] == 1

    def test_record_reprotect(self, collector):
        collector.record_reprotect("SSN_V1", "SSN_V2")
        data = collector.get_session_data()
        assert data["data_elements"]["SSN_V1"]["reprotect_source_count"] == 1
        assert data["data_elements"]["SSN_V2"]["reprotect_target_count"] == 1

    def test_multiple_operations_accumulate(self, collector):
        collector.record_protect("SSN")
        collector.record_protect("SSN")
        collector.record_protect("SSN")
        collector.record_unprotect("SSN")
        data = collector.get_session_data()
        assert data["data_elements"]["SSN"]["protect_count"] == 3
        assert data["data_elements"]["SSN"]["unprotect_count"] == 1

    def test_multiple_data_elements(self, collector):
        collector.record_protect("SSN")
        collector.record_protect("CC")
        data = collector.get_session_data()
        assert "SSN" in data["data_elements"]
        assert "CC" in data["data_elements"]

    def test_disabled_does_not_record(self, disabled_collector):
        disabled_collector.record_protect("SSN")
        data = disabled_collector.get_session_data()
        assert len(data["data_elements"]) == 0

    def test_session_data_includes_user(self, collector):
        data = collector.get_session_data()
        assert data["user"] == "testuser"

    def test_first_and_last_used_dates(self, collector):
        collector.record_protect("SSN")
        data = collector.get_session_data()
        today = date.today().isoformat()
        assert data["data_elements"]["SSN"]["first_used"] == today
        assert data["data_elements"]["SSN"]["last_used"] == today


# ──────────────────────────────────────────────────────────────
# StatsWriter — flush, merge, file locking
# ──────────────────────────────────────────────────────────────

class TestStatsWriter:

    @pytest.fixture
    def stats_file(self, tmp_path):
        path = tmp_path / "usage_stats.json"
        with patch.dict(os.environ, {"PTY_STATS_FILE": str(path)}):
            yield path

    def test_flush_creates_file(self, stats_file):
        session_data = {
            "user": "testuser",
            "data_elements": {
                "SSN": {
                    "protect_count": 5,
                    "unprotect_count": 2,
                    "reprotect_source_count": 0,
                    "reprotect_target_count": 0,
                    "first_used": "2025-06-01",
                    "last_used": "2025-06-01",
                }
            },
        }
        with patch.dict(os.environ, {"PTY_STATS_FILE": str(stats_file)}):
            flush_stats(session_data)
        assert stats_file.exists()
        content = json.loads(stats_file.read_text())
        assert content["data_elements"]["SSN"]["protect_count"] == 5

    def test_flush_merges_with_existing(self, stats_file):
        # Write initial
        session1 = {
            "user": "testuser",
            "data_elements": {
                "SSN": {
                    "protect_count": 3,
                    "unprotect_count": 1,
                    "reprotect_source_count": 0,
                    "reprotect_target_count": 0,
                    "first_used": "2025-06-01",
                    "last_used": "2025-06-01",
                }
            },
        }
        with patch.dict(os.environ, {"PTY_STATS_FILE": str(stats_file)}):
            flush_stats(session1)

        # Merge second session
        session2 = {
            "user": "testuser",
            "data_elements": {
                "SSN": {
                    "protect_count": 2,
                    "unprotect_count": 0,
                    "reprotect_source_count": 0,
                    "reprotect_target_count": 0,
                    "first_used": "2025-06-02",
                    "last_used": "2025-06-02",
                }
            },
        }
        with patch.dict(os.environ, {"PTY_STATS_FILE": str(stats_file)}):
            flush_stats(session2)

        content = json.loads(stats_file.read_text())
        assert content["data_elements"]["SSN"]["protect_count"] == 5
        assert content["data_elements"]["SSN"]["first_used"] == "2025-06-01"
        assert content["data_elements"]["SSN"]["last_used"] == "2025-06-02"

    def test_flush_graceful_degradation(self, tmp_path):
        """flush should never raise even if path is invalid."""
        with patch.dict(os.environ, {"PTY_STATS_FILE": "/nonexistent/deep/path/stats.json"}):
            # Should not raise
            flush_stats({"user": "x", "data_elements": {}})

    def test_stats_path_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PTY_STATS_FILE", None)
            path = _stats_path()
            assert ".protegrity" in str(path)
            assert "usage_stats.json" in str(path)

    def test_stats_path_custom(self):
        with patch.dict(os.environ, {"PTY_STATS_FILE": "/tmp/custom_stats.json"}):
            path = _stats_path()
            assert str(path) == "/tmp/custom_stats.json"


class TestMergeSession:

    def test_merge_new_data_element(self):
        existing = _empty_stats()
        session = {
            "user": "alice",
            "data_elements": {
                "CC": {
                    "protect_count": 10,
                    "unprotect_count": 3,
                    "reprotect_source_count": 0,
                    "reprotect_target_count": 0,
                    "first_used": "2025-06-01",
                    "last_used": "2025-06-01",
                }
            },
        }
        _merge_session(existing, session)
        assert "CC" in existing["data_elements"]
        assert existing["data_elements"]["CC"]["protect_count"] == 10

    def test_merge_accumulates_counts(self):
        existing = _empty_stats()
        existing["data_elements"]["SSN"] = {
            "protect_count": 5,
            "unprotect_count": 2,
            "reprotect_source_count": 0,
            "reprotect_target_count": 0,
            "first_used": "2025-06-01",
            "last_used": "2025-06-01",
        }
        session = {
            "user": "alice",
            "data_elements": {
                "SSN": {
                    "protect_count": 3,
                    "unprotect_count": 1,
                    "reprotect_source_count": 0,
                    "reprotect_target_count": 0,
                    "first_used": "2025-06-02",
                    "last_used": "2025-06-02",
                }
            },
        }
        _merge_session(existing, session)
        assert existing["data_elements"]["SSN"]["protect_count"] == 8
        assert existing["data_elements"]["SSN"]["unprotect_count"] == 3

    def test_merge_keeps_earliest_first_used(self):
        existing = _empty_stats()
        existing["data_elements"]["SSN"] = {
            "protect_count": 1,
            "unprotect_count": 0,
            "reprotect_source_count": 0,
            "reprotect_target_count": 0,
            "first_used": "2025-05-01",
            "last_used": "2025-05-01",
        }
        session = {
            "user": "alice",
            "data_elements": {
                "SSN": {
                    "protect_count": 1,
                    "unprotect_count": 0,
                    "reprotect_source_count": 0,
                    "reprotect_target_count": 0,
                    "first_used": "2025-06-01",
                    "last_used": "2025-06-01",
                }
            },
        }
        _merge_session(existing, session)
        assert existing["data_elements"]["SSN"]["first_used"] == "2025-05-01"

    def test_merge_policy_user(self):
        existing = _empty_stats()
        session = {"user": "bob", "data_elements": {}}
        _merge_session(existing, session)
        assert "bob" in existing["policy_users"]
        assert existing["policy_users"]["bob"]["session_count"] == 1

    def test_merge_policy_user_increments_session_count(self):
        existing = _empty_stats()
        session = {"user": "bob", "data_elements": {}}
        _merge_session(existing, session)
        _merge_session(existing, session)
        assert existing["policy_users"]["bob"]["session_count"] == 2
