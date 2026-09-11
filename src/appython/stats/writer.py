"""
Persistent storage for usage statistics.

Reads, merges, and writes the JSON stats file with file locking
for multi-process safety.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = "1.0"


# Cross-platform exclusive file locking. fcntl.flock is unix-only; Windows
# CPython (including Git Bash / MINGW which runs the Windows interpreter)
# does not ship it. msvcrt.locking provides equivalent semantics there.
if sys.platform == "win32":
    import msvcrt

    def _lock_exclusive(fd):
        # msvcrt requires a nonzero byte count. Lock 1 byte from offset 0;
        # this is sufficient as an advisory whole-file lock for our use.
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                return
            except OSError:
                # LK_LOCK blocks ~10s then raises; retry until acquired.
                continue

    def _unlock(fd):
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _lock_exclusive(fd):
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)


def _stats_path():
    """Return the path to the usage stats file."""
    custom = os.getenv("PTY_STATS_FILE")
    if custom:
        return Path(custom)
    return Path.home() / ".protegrity" / "usage_stats.json"


def _empty_stats():
    """Return a fresh empty stats structure."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "schema_version": _SCHEMA_VERSION,
        "collected_since": now,
        "last_updated": now,
        "data_elements": {},
        "policy_users": {},
    }


def _read_stats(path):
    """Read existing stats file. Returns None if not found or invalid."""
    if not path.is_file():
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if data.get("schema_version") == _SCHEMA_VERSION:
            return data
        return None
    except (json.JSONDecodeError, OSError):
        return None


def _merge_session(existing, session_data):
    """Merge a session's collected stats into the existing stats structure.

    Args:
        existing: The full stats dict (will be mutated).
        session_data: Dict from UsageCollector.get_session_data().
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    existing["last_updated"] = now

    # Merge data elements
    for de_name, de_stats in session_data.get("data_elements", {}).items():
        if de_name not in existing["data_elements"]:
            existing["data_elements"][de_name] = {
                "protect_count": 0,
                "unprotect_count": 0,
                "reprotect_source_count": 0,
                "reprotect_target_count": 0,
                "first_used": de_stats["first_used"],
                "last_used": de_stats["last_used"],
            }
        target = existing["data_elements"][de_name]
        target["protect_count"] += de_stats["protect_count"]
        target["unprotect_count"] += de_stats["unprotect_count"]
        target["reprotect_source_count"] += de_stats["reprotect_source_count"]
        target["reprotect_target_count"] += de_stats["reprotect_target_count"]
        # Update last_used if session is more recent
        if de_stats["last_used"] > target.get("last_used", ""):
            target["last_used"] = de_stats["last_used"]
        # Keep earliest first_used
        if de_stats["first_used"] < target.get("first_used", "9999-12-31"):
            target["first_used"] = de_stats["first_used"]

    # Merge policy user
    user = session_data.get("user")
    if user:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if user not in existing["policy_users"]:
            existing["policy_users"][user] = {
                "session_count": 0,
                "first_used": today,
                "last_used": today,
            }
        existing["policy_users"][user]["session_count"] += 1
        existing["policy_users"][user]["last_used"] = today


def flush_stats(session_data):
    """Flush session stats to disk with file locking.

    Reads existing stats, merges in session data, writes back atomically.
    Degrades gracefully — never raises exceptions to caller.

    Args:
        session_data: Dict from UsageCollector.get_session_data().
    """
    try:
        # During interpreter shutdown, modules may be None
        if json is None or os is None:
            return

        path = _stats_path()

        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        # Open (or create) with exclusive lock
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            _lock_exclusive(fd)
            # Read existing
            with os.fdopen(os.dup(fd), "r") as f:
                try:
                    content = f.read()
                    existing = json.loads(content) if content.strip() else None
                except (json.JSONDecodeError, OSError):
                    existing = None

            if existing is None or existing.get("schema_version") != _SCHEMA_VERSION:
                existing = _empty_stats()

            # Merge
            _merge_session(existing, session_data)

            # Write back (truncate and rewrite)
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            data_bytes = json.dumps(existing, indent=2).encode("utf-8")
            os.write(fd, data_bytes)
        finally:
            _unlock(fd)
            os.close(fd)

    except Exception as e:
        # Graceful degradation: log warning, never impact SDK operation
        # During interpreter shutdown, modules may already be torn down
        if json is not None and os is not None:
            logger.warning("Failed to write usage stats: %s", e)
