import sys
from unittest.mock import patch

import pytest

import pty_migrate.cli as cli


def test_cli_main_no_args():
    with patch.object(sys, "argv", ["pty-migrate"]):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code == 1


def test_cli_main_stats():
    with patch.object(sys, "argv", ["pty-migrate", "stats", "--json"]), \
         patch("pty_migrate.cli.run_stats", return_value=0) as mock_stats:
        res = cli.main()
        assert res == 0
        mock_stats.assert_called_once()


def test_cli_main_check():
    with patch.object(sys, "argv", ["pty-migrate", "check", "--with-protect-fn-test"]), \
         patch("pty_migrate.cli.run_check", return_value=0) as mock_check:
        res = cli.main()
        assert res == 0
        mock_check.assert_called_once()


def test_cli_main_create_policy():
    with patch.object(sys, "argv", ["pty-migrate", "create-policy", "--dry-run", "--ppc-user", "custom_user"]), \
         patch("pty_migrate.cli.run_create_policy", return_value=0) as mock_cp:
        res = cli.main()
        assert res == 0
        mock_cp.assert_called_once()
        args = mock_cp.call_args[0][0]
        assert args._ppc_user_explicit is True
