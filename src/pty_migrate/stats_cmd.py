"""pty-migrate stats command — display usage statistics summary."""

import json
import os
import sys
from pathlib import Path


def _load_stats(stats_file=None):
    """Load usage stats from file. CLI flag > env > config file > default."""
    from pty_migrate.config import resolve
    resolved = resolve(stats_file, "PTY_STATS_FILE", "stats_file",
                       str(Path.home() / ".protegrity" / "usage_stats.json"))
    path = Path(resolved)

    if not path.is_file():
        return None, path
    with open(path, "r") as f:
        return json.load(f), path


def run_stats(args):
    """Execute the stats command."""
    data, path = _load_stats(args.stats_file)

    if data is None:
        print(f"No usage statistics found at: {path}")
        print("Stats are collected automatically when using the SDK with Developer Edition.")
        print("Ensure DEV_EDITION_* environment variables are set and perform some operations.")
        return 1

    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    # Formatted output
    collected_since = data.get("collected_since", "unknown")
    last_updated = data.get("last_updated", "unknown")

    print(f"Usage Statistics (collected since {collected_since[:10]})")
    print("─" * 55)
    print(f"Last updated: {last_updated[:10]}")
    print()

    # Data elements
    data_elements = data.get("data_elements", {})
    if data_elements:
        print(f"Data Elements Used ({len(data_elements)}):")
        # Sort by protect_count descending
        sorted_des = sorted(
            data_elements.items(),
            key=lambda x: x[1].get("protect_count", 0),
            reverse=True,
        )
        for de_name, de_stats in sorted_des:
            protect = de_stats.get("protect_count", 0)
            unprotect = de_stats.get("unprotect_count", 0)
            reprotect_src = de_stats.get("reprotect_source_count", 0)
            reprotect_tgt = de_stats.get("reprotect_target_count", 0)
            last_used = de_stats.get("last_used", "—")
            line = f"  {de_name:<16} protect: {protect:<6} unprotect: {unprotect:<6}"
            if reprotect_src or reprotect_tgt:
                line += f" reprotect: {reprotect_src + reprotect_tgt:<4}"
            line += f" last: {last_used}"
            print(line)
    else:
        print("No data elements recorded yet.")

    print()

    # Policy users
    policy_users = data.get("policy_users", {})
    if policy_users:
        print(f"Policy Users ({len(policy_users)}):")
        sorted_users = sorted(
            policy_users.items(),
            key=lambda x: x[1].get("session_count", 0),
            reverse=True,
        )
        for user, user_stats in sorted_users:
            sessions = user_stats.get("session_count", 0)
            last_used = user_stats.get("last_used", "—")
            print(f"  {user:<16} sessions: {sessions:<6} last: {last_used}")
    else:
        print("No policy users recorded yet.")

    return 0
