import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest
import requests

import pty_migrate.check_cmd as check_cmd


def test_load_rules_index_success():
    idx = check_cmd._load_rules_index()
    assert idx is not None
    assert "user_to_role" in idx
    assert "de_name_to_id" in idx
    assert "rules" in idx


@patch("builtins.open", side_effect=OSError("File not found"))
def test_load_rules_index_error(mock_open):
    idx = check_cmd._load_rules_index()
    assert idx is None


def test_expected_round_trip():
    idx = {
        "user_to_role": {"alice": "1"},
        "de_name_to_id": {"name": "1"},
        "rules": {
            ("1", "1"): {"protect": True, "unProtect": True},
            ("1", "2"): {"protect": True, "unProtect": False},
        },
    }
    assert check_cmd._expected_round_trip(None, "alice", "name") is None
    assert check_cmd._expected_round_trip(idx, "bob", "name") is None
    assert check_cmd._expected_round_trip(idx, "alice", "ssn") is None
    assert check_cmd._expected_round_trip(idx, "alice", "name") is True
    idx["de_name_to_id"]["email"] = "2"
    assert check_cmd._expected_round_trip(idx, "alice", "email") is False


def test_expected_can_protect():
    idx = {
        "user_to_role": {"alice": "1"},
        "de_name_to_id": {"name": "1"},
        "rules": {
            ("1", "1"): {"protect": True, "unProtect": False},
        },
    }
    assert check_cmd._expected_can_protect(None, "alice", "name") is None
    assert check_cmd._expected_can_protect(idx, "bob", "name") is None
    assert check_cmd._expected_can_protect(idx, "alice", "name") is True


def test_load_stats(tmp_path):
    stats_data = {"schema_version": "1.0", "data_elements": {}}
    p = tmp_path / "stats.json"
    p.write_text(json.dumps(stats_data))
    loaded = check_cmd._load_stats(str(p))
    assert loaded == stats_data

    loaded_none = check_cmd._load_stats(str(tmp_path / "missing.json"))
    assert loaded_none is None


@patch("importlib.metadata.version")
@patch("appython.Protector")
def test_check_sdk_version_cases(mock_protector_cls, mock_pkg_version):
    # Case 1: ok
    mock_pkg_version.return_value = "1.2.2"
    mock_protector = MagicMock()
    mock_protector.get_version.return_value = "1.2.2"
    mock_protector_cls.return_value = mock_protector
    status, ver = check_cmd._check_sdk_version()
    assert status == "ok"
    assert ver == "1.2.2"

    # Case 2: old
    mock_protector.get_version.return_value = "1.1.0"
    status, ver = check_cmd._check_sdk_version()
    assert status == "old"

    # Case 3: load error
    mock_protector.get_version.side_effect = Exception("Failed import")
    status, ver = check_cmd._check_sdk_version()
    assert status == "load_error"

    # Case 4: missing
    import importlib.metadata
    mock_pkg_version.side_effect = importlib.metadata.PackageNotFoundError
    status, ver = check_cmd._check_sdk_version()
    assert status == "load_error" or status == "missing"


def test_check_java_sdk_version(tmp_path):
    # Directory missing
    with patch("pathlib.Path.home", return_value=tmp_path):
        ok, detail = check_cmd._check_java_sdk_version()
        assert ok is None

    # Directory with versions
    m2_repo = tmp_path / ".m2" / "repository" / "com" / "protegrity" / "application-protector-java"
    m2_repo.mkdir(parents=True)
    (m2_repo / "1.1.0").mkdir()
    (m2_repo / "1.0.5").mkdir()

    with patch("pathlib.Path.home", return_value=tmp_path):
        ok, detail = check_cmd._check_java_sdk_version()
        assert ok is True
        assert detail == "1.1.0"

    # Directory without valid versions
    empty_repo = tmp_path / "other" / ".m2" / "repository" / "com" / "protegrity" / "application-protector-java"
    empty_repo.mkdir(parents=True)
    (empty_repo / "abc").mkdir()
    with patch("pathlib.Path.home", return_value=tmp_path / "other"):
        ok, detail = check_cmd._check_java_sdk_version()
        assert ok is None


@patch("pty_migrate.check_cmd._sdk_cfg")
def test_check_te_host(mock_cfg):
    mock_cfg.return_value = {"protect_host": "cloudprotect.example.com"}
    ok, host = check_cmd._check_te_host()
    assert ok is True
    assert host == "cloudprotect.example.com"

    mock_cfg.return_value = {}
    ok, host = check_cmd._check_te_host()
    assert ok is False


@patch("pty_migrate.check_cmd._sdk_cfg")
def test_check_auth_mode_variations(mock_cfg):
    # Unset
    mock_cfg.return_value = {}
    ok, mode, detail = check_cmd._check_auth_mode()
    assert not ok
    assert "PTY_AUTH_MODE not set" in detail

    # aws_iam with profile
    mock_cfg.return_value = {"auth_mode": "aws_iam"}
    with patch.dict(os.environ, {"AWS_PROFILE": "dev-profile"}):
        ok, mode, detail = check_cmd._check_auth_mode()
        assert ok and "profile: dev-profile" in detail

    # aws_iam with keys
    with patch.dict(os.environ, {"AWS_PROFILE": "", "AWS_ACCESS_KEY_ID": "key", "AWS_SESSION_TOKEN": "token"}):
        ok, mode, detail = check_cmd._check_auth_mode()
        assert ok and "with session token" in detail

    # aws_iam missing creds
    with patch.dict(os.environ, {"AWS_PROFILE": "", "AWS_ACCESS_KEY_ID": ""}):
        ok, mode, detail = check_cmd._check_auth_mode()
        assert not ok and "No AWS credentials found" in detail

    # bearer_token static
    mock_cfg.return_value = {"auth_mode": "bearer_token", "static_token": "jwt123"}
    ok, mode, detail = check_cmd._check_auth_mode()
    assert ok and "static token present" in detail

    # bearer_token oauth2
    mock_cfg.return_value = {
        "auth_mode": "bearer_token",
        "token_endpoint": "https://auth.com",
        "client_id": "cid",
        "client_secret": "sec",
    }
    ok, mode, detail = check_cmd._check_auth_mode()
    assert ok and "oauth2 client_credentials configured" in detail

    # bearer_token missing
    mock_cfg.return_value = {"auth_mode": "bearer_token"}
    ok, mode, detail = check_cmd._check_auth_mode()
    assert not ok and "set PTY_STATIC_TOKEN" in detail

    # mtls
    mock_cfg.return_value = {"auth_mode": "mtls", "client_cert": "cert.pem", "client_key": "key.pem"}
    ok, mode, detail = check_cmd._check_auth_mode()
    assert ok and "cert: cert.pem" in detail

    mock_cfg.return_value = {"auth_mode": "mtls"}
    ok, mode, detail = check_cmd._check_auth_mode()
    assert not ok and "PTY_CLIENT_CERT" in detail

    # cognito / none
    mock_cfg.return_value = {"auth_mode": "cognito"}
    ok, mode, detail = check_cmd._check_auth_mode()
    assert ok and "Developer Edition" in detail

    mock_cfg.return_value = {"auth_mode": "none"}
    ok, mode, detail = check_cmd._check_auth_mode()
    assert ok and "no auth" in detail


def test_shell_export():
    with patch("os.name", "nt"):
        assert check_cmd._shell_export("VAR", "VAL") == '$env:VAR = "VAL"'
    with patch("os.name", "posix"):
        assert check_cmd._shell_export("VAR", "VAL") == 'export VAR=VAL'


def test_auth_fix_hints():
    assert len(check_cmd._auth_fix_hints("", "")) > 0
    assert len(check_cmd._auth_fix_hints("aws_iam", "")) > 0
    assert len(check_cmd._auth_fix_hints("bearer_token", "")) > 0
    assert len(check_cmd._auth_fix_hints("oauth2_client_credentials", "")) > 0
    assert len(check_cmd._auth_fix_hints("mtls", "")) > 0
    assert len(check_cmd._auth_fix_hints("other", "custom detail")) > 0


@patch("requests.get")
def test_check_endpoint_reachable(mock_get):
    # 200 OK
    resp = MagicMock(status_code=200)
    mock_get.return_value = resp
    ok, detail = check_cmd._check_endpoint_reachable("https://example.com")
    assert ok is True and "HTTP 200" in detail

    # SSLError then fallback success
    resp_warn = MagicMock(status_code=200)
    mock_get.side_effect = [requests.exceptions.SSLError("Untrusted"), resp_warn]
    ok, detail = check_cmd._check_endpoint_reachable("https://example.com")
    assert ok is True and "reachable (SSL warning)" in detail

    # ConnectionError
    mock_get.side_effect = requests.exceptions.ConnectionError()
    ok, detail = check_cmd._check_endpoint_reachable("https://example.com")
    assert ok is False and "Connection refused" in detail

    # Timeout
    mock_get.side_effect = requests.exceptions.Timeout()
    ok, detail = check_cmd._check_endpoint_reachable("https://example.com")
    assert ok is False and "Timeout" in detail


@patch("appython.Protector")
def test_check_auth_works(mock_protector_cls):
    mock_protector = MagicMock()
    mock_session = MagicMock()
    mock_protector.create_session.return_value = mock_session
    mock_protector_cls.return_value = mock_protector

    # Success
    mock_session.protect.return_value = "prot"
    ok, detail = check_cmd._check_auth_works()
    assert ok is True and "protect succeeded" in detail

    # 401 error
    mock_session.protect.side_effect = Exception("401 Unauthorized")
    ok, detail = check_cmd._check_auth_works()
    assert ok is False and "credentials rejected" in detail

    # Connection timeout
    mock_session.protect.side_effect = Exception("Connection timeout")
    ok, detail = check_cmd._check_auth_works()
    assert ok is False and "connection failed" in detail

    # Policy error (auth still worked)
    mock_session.protect.side_effect = Exception("Data element not found")
    ok, detail = check_cmd._check_auth_works()
    assert ok is True and "endpoint responded" in detail


@patch("appython.Protector")
def test_check_data_elements(mock_protector_cls):
    mock_protector = MagicMock()
    mock_session = MagicMock()
    mock_protector.create_session.return_value = mock_session
    mock_protector_cls.return_value = mock_protector

    # Round trip success
    mock_session.protect.return_value = "protected_val"
    mock_session.unprotect.return_value = "test_migration_check"
    ok, detail = check_cmd._check_data_elements(stats={})
    assert ok is True and "round-trip OK" in detail

    # Protect failure
    mock_session.protect.side_effect = Exception("DE failed")
    ok, detail = check_cmd._check_data_elements(stats={})
    assert ok is False and "protect failed" in detail

    # Unprotect failure
    mock_session.protect.side_effect = None
    mock_session.protect.return_value = "protected_val"
    mock_session.unprotect.side_effect = Exception("Unprotect error")
    ok, detail = check_cmd._check_data_elements(stats={})
    assert ok is False and "unprotect failed" in detail


def test_bundled_names():
    des = check_cmd._bundled_de_names()
    assert isinstance(des, list)
    assert len(des) > 0

    members = check_cmd._bundled_member_names()
    assert isinstance(members, set)
    assert len(members) > 0


@patch("pty_migrate.ppc_client.PPCClient")
def test_check_ppc_deployment(mock_ppc_cls):
    mock_client = MagicMock()
    mock_client.authenticate.return_value = None
    mock_client.list_datastores.return_value = [
        {"name": "DevEdition", "uid": "ds-123"}
    ]
    mock_client.list_data_elements.return_value = [
        {"name": "name"}, {"name": "ssn"}
    ]
    mock_client.list_roles.return_value = [
        {"name": "Superuser", "uid": "r-1"}
    ]
    mock_client.list_role_members.return_value = [
        {"name": "superuser"}
    ]
    mock_client.list_export_keys.return_value = ["key1"]
    mock_ppc_cls.return_value = mock_client

    ppc = {"host": "ppc.com", "user": "u", "password": "p"}
    stats = {
        "data_elements": {"name": {}},
        "policy_users": {"superuser": {}},
    }

    results, info = check_cmd._check_ppc_deployment(ppc, stats, full=False)
    assert info["dev_edition_uid"] == "ds-123"
    assert len(results) >= 4
    for label, ok, detail in results:
        assert ok is True


@patch("pty_migrate.check_cmd._check_sdk_version")
@patch("pty_migrate.check_cmd._check_te_host")
@patch("pty_migrate.check_cmd._check_auth_mode")
@patch("pty_migrate.check_cmd._check_endpoint_reachable")
@patch("pty_migrate.check_cmd._check_auth_works")
@patch("pty_migrate.check_cmd._check_data_elements")
def test_run_check_with_protect_fn_test(
    mock_de, mock_auth_w, mock_reach, mock_auth_m, mock_te_h, mock_sdk, capsys
):
    mock_sdk.return_value = ("ok", "1.2.2")
    mock_te_h.return_value = (True, "https://te.example.com")
    mock_auth_m.return_value = (True, "aws_iam", "profile: default")
    mock_reach.return_value = (True, "HTTP 200")
    mock_auth_w.return_value = (True, "authenticated")
    mock_de.return_value = (True, "round-trip OK")

    args = SimpleNamespace(
        sdk="python",
        stats_file=None,
        ppc_host=None,
        ppc_user=None,
        ppc_password=None,
        full=False,
        with_protect_fn_test=True,
    )
    res = check_cmd.run_check(args)
    assert res == 0
    captured = capsys.readouterr()
    assert "READY FOR MIGRATION" in captured.out
