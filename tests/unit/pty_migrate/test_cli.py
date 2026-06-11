"""Integration tests for pty-migrate CLI (PTY-151139)."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.migration

# Ensure subprocess calls can find the package
_SRC_DIR = str(Path(__file__).resolve().parents[3] / "src")
_SUBPROCESS_ENV = {**os.environ, "PYTHONPATH": _SRC_DIR + os.pathsep + os.environ.get("PYTHONPATH", "")}

from pty_migrate.cli import main
from pty_migrate.stats_cmd import run_stats
from pty_migrate.check_cmd import run_check
from pty_migrate.create_policy_cmd import run_create_policy


# ──────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def sample_stats_file(tmp_path):
    """Create a sample usage stats JSON file."""
    stats = {
        "schema_version": "1.0",
        "collected_since": "2025-06-01T00:00:00Z",
        "last_updated": "2025-06-10T12:00:00Z",
        "sdk": "appython",
        "sdk_version": "1.2.0",
        "data_elements": {
            "SSN": {
                "protect_count": 100,
                "unprotect_count": 50,
                "reprotect_source_count": 5,
                "reprotect_target_count": 0,
                "first_used": "2025-06-01",
                "last_used": "2025-06-10",
            },
            "CC": {
                "protect_count": 30,
                "unprotect_count": 10,
                "reprotect_source_count": 0,
                "reprotect_target_count": 5,
                "first_used": "2025-06-02",
                "last_used": "2025-06-10",
            },
        },
        "policy_users": {
            "alice": {
                "session_count": 10,
                "first_used": "2025-06-01",
                "last_used": "2025-06-10",
            },
            "bob": {
                "session_count": 3,
                "first_used": "2025-06-05",
                "last_used": "2025-06-09",
            },
        },
    }
    stats_file = tmp_path / "usage_stats.json"
    stats_file.write_text(json.dumps(stats, indent=2))
    return str(stats_file)


# ──────────────────────────────────────────────────────────────
# stats command
# ──────────────────────────────────────────────────────────────

class TestStatsCommand:

    def test_stats_with_json_output(self, sample_stats_file, capsys):
        args = SimpleNamespace(stats_file=sample_stats_file, json=True)
        result = run_stats(args)
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["data_elements"]["SSN"]["protect_count"] == 100

    def test_stats_formatted_output(self, sample_stats_file, capsys):
        args = SimpleNamespace(stats_file=sample_stats_file, json=False)
        result = run_stats(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "SSN" in captured.out
        assert "CC" in captured.out
        assert "alice" in captured.out

    def test_stats_missing_file(self, tmp_path, capsys):
        args = SimpleNamespace(stats_file=str(tmp_path / "nonexistent.json"), json=False)
        result = run_stats(args)
        assert result == 1
        captured = capsys.readouterr()
        assert "No usage statistics found" in captured.out

    def test_stats_cli_entry_point(self, sample_stats_file):
        """Test via subprocess — real CLI invocation."""
        result = subprocess.run(
            [sys.executable, "-m", "pty_migrate.cli", "stats",
             "--stats-file", sample_stats_file, "--json"],
            capture_output=True, text=True, env=_SUBPROCESS_ENV
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "data_elements" in data


# ──────────────────────────────────────────────────────────────
# create-policy command
# ──────────────────────────────────────────────────────────────

class TestCreatePolicyCommand:

    def test_create_policy_dry_run_with_stats(self, sample_stats_file, capsys):
        args = SimpleNamespace(
            stats_file=sample_stats_file,
            ppc_host="ppc.example.com",
            ppc_user="workbench",
            ppc_password="pass",
            ppc_port=443,
            full=False,
            dry_run=True,
        )
        result = run_create_policy(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out

    def test_create_policy_dry_run_full_mode(self, tmp_path, capsys):
        args = SimpleNamespace(
            stats_file=str(tmp_path / "nonexistent.json"),
            ppc_host="ppc.example.com",
            ppc_user="workbench",
            ppc_password="pass",
            ppc_port=443,
            full=True,
            dry_run=True,
        )
        result = run_create_policy(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out
        # Full mode should include all data elements
        assert "Data elements:" in captured.out

    def test_create_policy_no_stats_creates_full(self, tmp_path, capsys):
        """No stats and no --full → creates full DE policy (fallback)."""
        args = SimpleNamespace(
            stats_file=str(tmp_path / "missing.json"),
            ppc_host="ppc.example.com",
            ppc_user="workbench",
            ppc_password="pass",
            ppc_port=443,
            full=False,
            dry_run=True,
        )
        result = run_create_policy(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "complete DE policy" in captured.out

    @patch("pty_migrate.create_policy_cmd.PPCClient")
    def test_create_policy_auth_failure(self, mock_ppc_cls, sample_stats_file, capsys):
        mock_client = MagicMock()
        mock_client.authenticate.side_effect = Exception("Connection refused")
        mock_ppc_cls.return_value = mock_client

        args = SimpleNamespace(
            stats_file=sample_stats_file,
            ppc_host="ppc.example.com",
            ppc_user="workbench",
            ppc_password="pass",
            ppc_port=443,
            full=False,
            dry_run=False,
        )
        result = run_create_policy(args)
        assert result == 1
        captured = capsys.readouterr()
        assert "Authentication failed" in captured.out

    @patch("pty_migrate.create_policy_cmd.PPCClient")
    def test_create_policy_success_delta(self, mock_ppc_cls, sample_stats_file, capsys):
        mock_client = MagicMock()
        # Simulate PPC with nothing existing
        mock_client.is_pim_initialized.return_value = True
        mock_client.list_datastores.return_value = []
        mock_client.list_sources.return_value = []
        mock_client.list_roles.return_value = []
        mock_client.list_alphabets.return_value = []
        mock_client.list_masks.return_value = []
        mock_client.list_data_elements.return_value = []
        mock_client.list_applications.return_value = []
        mock_client.list_policies.return_value = []
        # All creates succeed
        mock_client.post_resource.return_value = (True, MagicMock())
        mock_client.create_datastore.return_value = (True, MagicMock())
        mock_client.create_source.return_value = (True, MagicMock())
        mock_client.create_role.return_value = (True, MagicMock())
        mock_client.create_alphabet.return_value = (True, MagicMock())
        mock_client.create_mask.return_value = (True, MagicMock())
        mock_client.create_data_element.return_value = (True, MagicMock())
        mock_client.create_application.return_value = (True, MagicMock())
        mock_client.create_policy.return_value = (True, MagicMock())
        mock_client.create_rule.return_value = (True, MagicMock())
        mock_client.deploy.return_value = (True, MagicMock())
        mock_client.init_pim.return_value = True
        mock_ppc_cls.return_value = mock_client

        args = SimpleNamespace(
            stats_file=sample_stats_file,
            ppc_host="ppc.example.com",
            ppc_user="workbench",
            ppc_password="pass",
            ppc_port=443,
            full=False,
            dry_run=False,
        )
        result = run_create_policy(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "Done" in captured.out

    @patch("pty_migrate.create_policy_cmd.PPCClient")
    def test_create_policy_idempotent(self, mock_ppc_cls, sample_stats_file, capsys):
        """If PPC already has all resources, nothing new gets created."""
        mock_client = MagicMock()
        mock_client.is_pim_initialized.return_value = True
        mock_client.init_pim.return_value = True
        # Simulate PPC already has the DEs and roles
        mock_client.list_datastores.return_value = [{"name": "DevEdition"}]
        mock_client.list_sources.return_value = [{"name": "DevEditionSource"}]
        mock_client.list_roles.return_value = [{"name": "Superuser"}, {"name": "Admin"}]
        mock_client.list_alphabets.return_value = [
            {"label": "latin_german_numeric"}, {"label": "latin_french_numeric"},
            {"label": "latin_german"}, {"label": "latin_french"},
        ]
        mock_client.list_masks.return_value = [{"name": "masking"}]
        mock_client.list_data_elements.return_value = [{"name": "SSN"}, {"name": "CC"}]
        mock_client.list_applications.return_value = [{"name": "DevEditionTrustedApp"}]
        mock_client.list_policies.return_value = [{"name": "DevEditionPolicy"}]
        # Rules/members attempted but 409
        mock_client.post_resource.return_value = (False, MagicMock())
        mock_client.create_alphabet.return_value = (False, MagicMock())
        mock_client.create_mask.return_value = (False, MagicMock())
        mock_client.create_rule.return_value = (False, MagicMock())
        mock_client.deploy.return_value = (True, MagicMock())
        mock_ppc_cls.return_value = mock_client

        args = SimpleNamespace(
            stats_file=sample_stats_file,
            ppc_host="ppc.example.com",
            ppc_user="workbench",
            ppc_password="pass",
            ppc_port=443,
            full=False,
            dry_run=False,
        )
        result = run_create_policy(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "Nothing new to create" in captured.out or "Done" in captured.out


# ──────────────────────────────────────────────────────────────
# check command
# ──────────────────────────────────────────────────────────────

class TestCheckCommand:

    @patch("pty_migrate.check_cmd._check_sdk_version")
    @patch("pty_migrate.check_cmd._check_te_host")
    @patch("pty_migrate.check_cmd._check_auth_mode")
    def test_check_sdk_version_pass(self, mock_auth, mock_host, mock_version, capsys):
        mock_version.return_value = ("ok", "1.2.0")
        mock_host.return_value = (False, "")
        mock_auth.return_value = (False, "", "PTY_AUTH_MODE not set")

        args = SimpleNamespace(
            sdk="python", stats_file=None,
            ppc_host=None, ppc_user=None, ppc_password=None,
            full=False, with_protect_fn_test=True,
        )
        run_check(args)
        captured = capsys.readouterr()
        assert "1.2.0" in captured.out

    @patch("pty_migrate.check_cmd._check_sdk_version")
    @patch("pty_migrate.check_cmd._check_te_host")
    @patch("pty_migrate.check_cmd._check_auth_mode")
    def test_check_sdk_version_fail(self, mock_auth, mock_host, mock_version, capsys):
        mock_version.return_value = ("old", "1.1.0")
        mock_host.return_value = (False, "")
        mock_auth.return_value = (False, "", "PTY_AUTH_MODE not set")

        args = SimpleNamespace(
            sdk="python", stats_file=None,
            ppc_host=None, ppc_user=None, ppc_password=None,
            full=False, with_protect_fn_test=True,
        )
        run_check(args)
        captured = capsys.readouterr()
        assert "1.1.0" in captured.out

    def test_check_cli_entry_point(self):
        """Test via subprocess — real CLI invocation."""
        result = subprocess.run(
            [sys.executable, "-m", "pty_migrate.cli", "check", "--sdk", "python"],
            capture_output=True, text=True,
            env={**_SUBPROCESS_ENV, "PTY_AUTH_MODE": "", "PTY_CP_HOST": ""}
        )
        # Should exit (may fail checks, but CLI should run without error)
        assert result.returncode in (0, 1)


# ──────────────────────────────────────────────────────────────
# CLI argparse validation
# ──────────────────────────────────────────────────────────────

class TestCLIArgParsing:

    def test_no_command_shows_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "pty_migrate.cli"],
            capture_output=True, text=True, env=_SUBPROCESS_ENV
        )
        assert result.returncode == 1
        assert "pty-migrate" in result.stderr or "pty-migrate" in result.stdout

    def test_unknown_command_error(self):
        result = subprocess.run(
            [sys.executable, "-m", "pty_migrate.cli", "invalid_cmd"],
            capture_output=True, text=True, env=_SUBPROCESS_ENV
        )
        # argparse will return error for unknown command
        assert result.returncode != 0

    def test_create_policy_requires_ppc_host(self, tmp_path):
        env = {k: v for k, v in _SUBPROCESS_ENV.items() if not k.startswith("PTY_")}
        # Point at a non-existent config file so the user's real
        # ~/.protegrity/config.yaml doesn't leak in.
        env["PTY_CONFIG_FILE"] = str(tmp_path / "no-such-config.yaml")
        result = subprocess.run(
            [sys.executable, "-m", "pty_migrate.cli", "create-policy",
             "--ppc-password", "test"],
            capture_output=True, text=True, env=env
        )
        assert result.returncode != 0
        combined = (result.stdout + result.stderr).lower()
        assert "ppc-host" in combined or "pty_ppc_host" in combined or "required" in combined


# ──────────────────────────────────────────────────────────────
# Config resolver (CLI > env > config file > default)
# ──────────────────────────────────────────────────────────────

class TestConfigResolver:
    """Verify pty-migrate honours the config-file fallback for PPC settings."""

    def _patch_file_cfg(self, monkeypatch, cfg):
        from pty_migrate import config as ptyc
        ptyc._file_cfg.cache_clear()
        monkeypatch.setattr(ptyc, "_file_cfg", lambda: cfg)

    def test_file_used_when_env_and_cli_unset(self, monkeypatch):
        from pty_migrate.config import resolve
        for k in ("PTY_PPC_HOST", "PTY_PPC_USER"):
            monkeypatch.delenv(k, raising=False)
        self._patch_file_cfg(monkeypatch, {"ppc_host": "file-host", "ppc_user": "file-user"})
        assert resolve(None, "PTY_PPC_HOST", "ppc_host") == "file-host"
        assert resolve(None, "PTY_PPC_USER", "ppc_user", "workbench") == "file-user"

    def test_env_overrides_file(self, monkeypatch):
        from pty_migrate.config import resolve
        monkeypatch.setenv("PTY_PPC_HOST", "env-host")
        self._patch_file_cfg(monkeypatch, {"ppc_host": "file-host"})
        assert resolve(None, "PTY_PPC_HOST", "ppc_host") == "env-host"

    def test_cli_overrides_env_and_file(self, monkeypatch):
        from pty_migrate.config import resolve
        monkeypatch.setenv("PTY_PPC_HOST", "env-host")
        self._patch_file_cfg(monkeypatch, {"ppc_host": "file-host"})
        assert resolve("cli-host", "PTY_PPC_HOST", "ppc_host") == "cli-host"

    def test_default_used_when_nothing_set(self, monkeypatch):
        from pty_migrate.config import resolve
        monkeypatch.delenv("PTY_PPC_USER", raising=False)
        self._patch_file_cfg(monkeypatch, {})
        assert resolve(None, "PTY_PPC_USER", "ppc_user", "workbench") == "workbench"

    def test_password_never_read_from_file_by_default(self, tmp_path, monkeypatch, capsys):
        """Regression guard: without `allow_secrets_in_file`, file passwords are dropped."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("ppc_password: should-be-ignored\n")
        cfg.chmod(0o600)
        monkeypatch.setenv("PTY_CONFIG_FILE", str(cfg))
        monkeypatch.delenv("PTY_PPC_PASSWORD", raising=False)
        from pty_migrate import config as ptyc
        ptyc._file_cfg.cache_clear()
        from pty_migrate.check_cmd import _resolve_ppc_args
        args = SimpleNamespace(ppc_host=None, ppc_user=None, ppc_password=None)
        ppc = _resolve_ppc_args(args)
        assert ppc["password"] is None

    def test_check_cmd_picks_up_ppc_host_from_file(self, monkeypatch):
        monkeypatch.delenv("PTY_PPC_HOST", raising=False)
        self._patch_file_cfg(monkeypatch, {"ppc_host": "yaml-ppc.example"})
        from pty_migrate.check_cmd import _resolve_ppc_args
        args = SimpleNamespace(ppc_host=None, ppc_user=None, ppc_password=None)
        assert _resolve_ppc_args(args)["host"] == "yaml-ppc.example"


# ──────────────────────────────────────────────────────────────
# Password from file (opt-in + chmod 600)
# ──────────────────────────────────────────────────────────────

class TestPasswordFromFile:
    """`allow_secrets_in_file: true` + chmod 600 lets passwords live in YAML."""

    def _write_cfg(self, tmp_path, body, mode=0o600):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(body)
        cfg.chmod(mode)
        return cfg

    def _reset_cache(self):
        from pty_migrate import config as ptyc
        ptyc._file_cfg.cache_clear()

    def test_password_dropped_without_opt_in(self, tmp_path, monkeypatch, capsys):
        cfg = self._write_cfg(tmp_path, "ppc_password: secret\n")
        monkeypatch.setenv("PTY_CONFIG_FILE", str(cfg))
        monkeypatch.delenv("PTY_PPC_PASSWORD", raising=False)
        self._reset_cache()
        from pty_migrate.config import resolve_password
        val, source = resolve_password(None, "PTY_PPC_PASSWORD", "ppc_password")
        assert val is None and source is None
        err = capsys.readouterr().err
        assert "allow_secrets_in_file" in err

    def test_password_read_with_opt_in_and_secure_perms(self, tmp_path, monkeypatch):
        cfg = self._write_cfg(
            tmp_path, "allow_secrets_in_file: true\nppc_password: secret\n", mode=0o600
        )
        monkeypatch.setenv("PTY_CONFIG_FILE", str(cfg))
        monkeypatch.delenv("PTY_PPC_PASSWORD", raising=False)
        self._reset_cache()
        from pty_migrate.config import resolve_password
        val, source = resolve_password(None, "PTY_PPC_PASSWORD", "ppc_password")
        assert val == "secret"
        assert source == "file"

    def test_password_dropped_with_loose_perms_even_when_opted_in(self, tmp_path, monkeypatch, capsys):
        if os.name == "nt":
            pytest.skip("POSIX-permission check is no-op on Windows")
        cfg = self._write_cfg(
            tmp_path, "allow_secrets_in_file: true\nppc_password: secret\n", mode=0o644
        )
        monkeypatch.setenv("PTY_CONFIG_FILE", str(cfg))
        monkeypatch.delenv("PTY_PPC_PASSWORD", raising=False)
        self._reset_cache()
        from pty_migrate.config import resolve_password
        val, source = resolve_password(None, "PTY_PPC_PASSWORD", "ppc_password")
        assert val is None and source is None
        err = capsys.readouterr().err
        assert "chmod 600" in err

    def test_env_password_beats_file_password(self, tmp_path, monkeypatch):
        cfg = self._write_cfg(
            tmp_path, "allow_secrets_in_file: true\nppc_password: file-pw\n", mode=0o600
        )
        monkeypatch.setenv("PTY_CONFIG_FILE", str(cfg))
        monkeypatch.setenv("PTY_PPC_PASSWORD", "env-pw")
        self._reset_cache()
        from pty_migrate.config import resolve_password
        val, source = resolve_password(None, "PTY_PPC_PASSWORD", "ppc_password")
        assert (val, source) == ("env-pw", "env")

    def test_cli_password_beats_everything(self, tmp_path, monkeypatch):
        cfg = self._write_cfg(
            tmp_path, "allow_secrets_in_file: true\nppc_password: file-pw\n", mode=0o600
        )
        monkeypatch.setenv("PTY_CONFIG_FILE", str(cfg))
        monkeypatch.setenv("PTY_PPC_PASSWORD", "env-pw")
        self._reset_cache()
        from pty_migrate.config import resolve_password
        val, source = resolve_password("cli-pw", "PTY_PPC_PASSWORD", "ppc_password")
        assert (val, source) == ("cli-pw", "cli")
