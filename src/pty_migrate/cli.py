"""CLI entry point for pty-migrate."""

import argparse
import os
import sys

from pty_migrate.stats_cmd import run_stats
from pty_migrate.create_policy_cmd import run_create_policy
from pty_migrate.check_cmd import run_check


def main():
    parser = argparse.ArgumentParser(
        prog="pty-migrate",
        description="Protegrity Developer Edition to Team Edition migration tool",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # stats
    stats_parser = subparsers.add_parser("stats", help="View local usage statistics")
    stats_parser.add_argument(
        "--stats-file", help="Path to usage stats JSON (default: ~/.protegrity/usage_stats.json)"
    )
    stats_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # create-policy
    cp_parser = subparsers.add_parser("create-policy", help="Create DE policy on PPC (Team Edition)")
    cp_parser.add_argument("--ppc-host",
                           help="PPC hostname or IP (or set PTY_PPC_HOST)")
    cp_parser.add_argument("--ppc-user",
                           help="PPC username (or set PTY_PPC_USER; default: admin)")
    cp_parser.add_argument("--ppc-password",
                           help="PPC admin password. PREFER env var PTY_PPC_PASSWORD "
                                "(passing on the command line leaks into shell history); "
                                "if neither is set, you'll be prompted interactively.")
    cp_parser.add_argument("--workbench-password",
                           help="Password for the auto-provisioned 'workbench' PIM user "
                                "(or set PTY_WORKBENCH_PASSWORD). "
                                "Defaults to --ppc-password if omitted.")
    cp_parser.add_argument("--ppc-port", type=int, default=None,
                           help="PPC port (or set PTY_PPC_PORT; default: 443)")
    cp_parser.add_argument(
        "--stats-file", help="Path to usage stats JSON (default: ~/.protegrity/usage_stats.json)"
    )
    cp_parser.add_argument("--full", action="store_true",
                           help="Create full DE policy (ignore stats filter)")
    cp_parser.add_argument("--dry-run", action="store_true",
                           help="Show what would be created without calling PPC")

    # check
    check_parser = subparsers.add_parser("check", help="Pre-flight migration readiness validation")
    check_parser.add_argument("--sdk", choices=["python", "java"], default="python", help="SDK to check")
    check_parser.add_argument("--stats-file", help="Path to usage stats JSON")
    check_parser.add_argument("--ppc-host",
                              help="PPC hostname (or set PTY_PPC_HOST). "
                                   "Required unless --with-protect-fn-test is given.")
    check_parser.add_argument("--ppc-user",
                              help="PPC username (or set PTY_PPC_USER; default: workbench)")
    check_parser.add_argument("--ppc-password",
                              help="PPC password. PREFER env var PTY_PPC_PASSWORD "
                                   "(passing on the command line leaks into shell history).")
    check_parser.add_argument("--full", action="store_true",
                              help="Verify all bundled Developer Edition data elements on PPC "
                                   "(default: only DEs found in local usage stats)")
    check_parser.add_argument("--with-protect-fn-test", action="store_true",
                              help="Also run protect/unprotect against Cloud Protect. "
                                   "Use alone (without PPC creds) for a smoke-only check.")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Track whether --ppc-user was explicitly provided (CLI flag, env, or config file)
    if args.command == "create-policy":
        from pty_migrate.config import file_has
        args._ppc_user_explicit = (
            any(a.startswith("--ppc-user") for a in sys.argv)
            or bool(os.getenv("PTY_PPC_USER"))
            or file_has("ppc_user")
        )

    if args.command == "stats":
        return run_stats(args)
    elif args.command == "create-policy":
        return run_create_policy(args)
    elif args.command == "check":
        return run_check(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
