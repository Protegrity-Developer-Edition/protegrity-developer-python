from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from pty_migrate.create_policy_cmd import run_create_policy


def test_create_policy_missing_credentials(capsys):
    args = SimpleNamespace(
        ppc_host=None,
        ppc_user=None,
        ppc_password=None,
        stats_file=None,
    )
    res = run_create_policy(args)
    assert res == 1
    captured = capsys.readouterr()
    assert "Missing PPC credentials" in captured.out


def test_create_policy_password_sources(capsys):
    # Password via cli
    args = SimpleNamespace(
        ppc_host="ppc.example.com",
        ppc_user="admin",
        ppc_password="clipassword",
        workbench_password="wbpassword",
        stats_file=None,
        dry_run=True,
    )
    res = run_create_policy(args)
    assert res == 0
    captured = capsys.readouterr()
    assert "recorded in shell history" in captured.out


@patch("pty_migrate.create_policy_cmd.PPCClient")
def test_create_policy_auth_failure(mock_ppc_cls, capsys):
    mock_client = MagicMock()
    mock_client.authenticate.side_effect = Exception("401 Unauthorized")
    mock_ppc_cls.return_value = mock_client

    args = SimpleNamespace(
        ppc_host="ppc.example.com",
        ppc_user="admin",
        ppc_password="pass",
        workbench_password=None,
        stats_file=None,
        dry_run=False,
        _ppc_user_explicit=True,
    )
    res = run_create_policy(args)
    assert res == 1
    captured = capsys.readouterr()
    assert "Authentication failed" in captured.out
