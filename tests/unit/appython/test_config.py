"""Unit tests for SDK config resolution and conflict detection.

Covers `appython.service.config.load_config` — the entry point that
turns env vars + config file into the dict consumed by every other
SDK component. This is the heart of the DE→TE migration plumbing.
"""

import os
from unittest.mock import patch

import pytest

from appython.service import config as config_mod
from appython.service.config import load_config

pytestmark = pytest.mark.migration


# Every test starts from a clean slate so leftover env doesn't leak in.
_MIGRATION_ENV_KEYS = (
    "PTY_AUTH_MODE",
    "PTY_CP_HOST",
    "PTY_API_VERSION",
    "PTY_REQUEST_TIMEOUT",
    "PTY_MAX_RETRIES",
    "PTY_TOKEN_ENDPOINT",
    "PTY_CLIENT_ID",
    "PTY_CLIENT_SECRET",
    "PTY_STATIC_TOKEN",
    "PTY_CLIENT_CERT",
    "PTY_CLIENT_KEY",
    "PTY_CA_CERT",
    "PTY_CONFIG_FILE",
    "DEV_EDITION_EMAIL",
    "DEV_EDITION_PASSWORD",
    "DEV_EDITION_API_KEY",
    "DEV_EDITION_HOST",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in _MIGRATION_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    # Default: no config file. Individual tests override with monkeypatch.
    monkeypatch.setattr(config_mod, "_load_file_config", lambda: {})
    yield


# ── Defaults ───────────────────────────────────────────────────────────────


class TestDefaults:

    def test_defaults_when_no_env_or_file(self):
        cfg = load_config()
        assert cfg["version"] == "1"
        assert cfg["request_timeout"] == 30
        assert cfg["max_retries"] == 3
        assert cfg["auth_mode"] is None
        assert cfg["protect_host"] is None


# ── Resolution precedence: env > file > default ────────────────────────────


class TestResolutionPrecedence:

    def test_env_beats_file(self, monkeypatch):
        monkeypatch.setattr(
            config_mod, "_load_file_config",
            lambda: {"protect_host": "https://from-file"},
        )
        monkeypatch.setenv("PTY_CP_HOST", "https://from-env")
        assert load_config()["protect_host"] == "https://from-env"

    def test_file_beats_default(self, monkeypatch):
        monkeypatch.setattr(
            config_mod, "_load_file_config",
            lambda: {"request_timeout": "45"},
        )
        assert load_config()["request_timeout"] == 45

    def test_env_int_parsed(self, monkeypatch):
        monkeypatch.setenv("PTY_REQUEST_TIMEOUT", "7")
        monkeypatch.setenv("PTY_MAX_RETRIES", "1")
        cfg = load_config()
        assert cfg["request_timeout"] == 7
        assert cfg["max_retries"] == 1


# ── Auth mode auto-detection ───────────────────────────────────────────────


class TestAutoDetectAuthMode:

    def test_de_vars_select_cognito(self, monkeypatch):
        monkeypatch.setenv("DEV_EDITION_EMAIL", "u@e")
        monkeypatch.setenv("DEV_EDITION_PASSWORD", "p")
        monkeypatch.setenv("DEV_EDITION_API_KEY", "k")
        cfg = load_config()
        assert cfg["auth_mode"] == "cognito"
        # Backward compat: no PTY_CP_HOST, but cognito gets a URL built from DE host
        assert cfg["protect_host"].endswith("api.developer-edition.protegrity.com")

    def test_de_host_override_used_when_pty_cp_host_missing(self, monkeypatch):
        monkeypatch.setenv("DEV_EDITION_EMAIL", "u@e")
        monkeypatch.setenv("DEV_EDITION_PASSWORD", "p")
        monkeypatch.setenv("DEV_EDITION_HOST", "custom.dev.example.com")
        cfg = load_config()
        assert cfg["protect_host"] == "https://custom.dev.example.com"

    def test_cp_host_plus_aws_creds_selects_aws_iam(self, monkeypatch):
        monkeypatch.setenv("PTY_CP_HOST", "https://cp.example.com/pty")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA...")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
        cfg = load_config()
        assert cfg["auth_mode"] == "aws_iam"

    def test_explicit_mode_overrides_detection(self, monkeypatch):
        # DE vars present, but caller explicitly asked for bearer_token.
        monkeypatch.setenv("DEV_EDITION_EMAIL", "u@e")
        monkeypatch.setenv("DEV_EDITION_PASSWORD", "p")
        monkeypatch.setenv("PTY_CP_HOST", "https://cp.example.com/pty")
        monkeypatch.setenv("PTY_AUTH_MODE", "bearer_token")
        monkeypatch.setenv("PTY_STATIC_TOKEN", "tok")
        assert load_config()["auth_mode"] == "bearer_token"


# ── Conflict detection ─────────────────────────────────────────────────────


class TestConflictDetection:

    def test_aws_iam_without_cp_host_raises(self, monkeypatch):
        monkeypatch.setenv("PTY_AUTH_MODE", "aws_iam")
        with pytest.raises(EnvironmentError) as exc:
            load_config()
        # Hint should name the missing var so the user can act.
        assert "PTY_CP_HOST" in str(exc.value)

    def test_aws_iam_without_cp_host_de_vars_present_mentions_de(self, monkeypatch):
        monkeypatch.setenv("PTY_AUTH_MODE", "aws_iam")
        monkeypatch.setenv("DEV_EDITION_EMAIL", "u@e")
        monkeypatch.setenv("DEV_EDITION_PASSWORD", "p")
        with pytest.raises(EnvironmentError) as exc:
            load_config()
        # Suggests removing leftover DE vars rather than adding a TE host.
        assert "AWS_ACCESS_KEY_ID" in str(exc.value)
        assert "PTY_AUTH_MODE" in str(exc.value)

    def test_both_de_and_te_credentials_without_mode_raises(self, monkeypatch):
        monkeypatch.setenv("DEV_EDITION_EMAIL", "u@e")
        monkeypatch.setenv("DEV_EDITION_PASSWORD", "p")
        monkeypatch.setenv("PTY_CP_HOST", "https://cp.example.com/pty")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA...")
        with pytest.raises(EnvironmentError) as exc:
            load_config()
        assert "DEV_EDITION_EMAIL" in str(exc.value)
        assert "PTY_CP_HOST" in str(exc.value)

    def test_aws_iam_with_leftover_de_vars_warns(self, monkeypatch):
        monkeypatch.setenv("PTY_AUTH_MODE", "aws_iam")
        monkeypatch.setenv("PTY_CP_HOST", "https://cp.example.com/pty")
        monkeypatch.setenv("DEV_EDITION_EMAIL", "u@e")
        monkeypatch.setenv("DEV_EDITION_PASSWORD", "p")
        with pytest.warns(UserWarning, match="DEV_EDITION_"):
            load_config()

    def test_cognito_with_leftover_te_vars_warns(self, monkeypatch):
        monkeypatch.setenv("PTY_AUTH_MODE", "cognito")
        monkeypatch.setenv("PTY_CP_HOST", "https://cp.example.com/pty")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA...")
        # Need DE vars set so cognito has something to work with
        monkeypatch.setenv("DEV_EDITION_EMAIL", "u@e")
        monkeypatch.setenv("DEV_EDITION_PASSWORD", "p")
        with pytest.warns(UserWarning, match="Team Edition"):
            load_config()


# ── TE-mode credentials surface in config ──────────────────────────────────


class TestModeSpecificFields:

    def test_bearer_token_fields_pass_through(self, monkeypatch):
        monkeypatch.setenv("PTY_AUTH_MODE", "bearer_token")
        monkeypatch.setenv("PTY_CP_HOST", "https://cp.example.com/pty")
        monkeypatch.setenv("PTY_STATIC_TOKEN", "tok-123")
        monkeypatch.setenv("PTY_TOKEN_ENDPOINT", "https://idp/oauth/token")
        monkeypatch.setenv("PTY_CLIENT_ID", "client")
        monkeypatch.setenv("PTY_CLIENT_SECRET", "secret")
        cfg = load_config()
        assert cfg["static_token"] == "tok-123"
        assert cfg["token_endpoint"] == "https://idp/oauth/token"
        assert cfg["client_id"] == "client"
        assert cfg["client_secret"] == "secret"

    def test_mtls_fields_pass_through(self, monkeypatch):
        monkeypatch.setenv("PTY_AUTH_MODE", "mtls")
        monkeypatch.setenv("PTY_CP_HOST", "https://cp.example.com/pty")
        monkeypatch.setenv("PTY_CLIENT_CERT", "/etc/ssl/client.pem")
        monkeypatch.setenv("PTY_CLIENT_KEY", "/etc/ssl/client.key")
        monkeypatch.setenv("PTY_CA_CERT", "/etc/ssl/ca.pem")
        cfg = load_config()
        assert cfg["client_cert"] == "/etc/ssl/client.pem"
        assert cfg["client_key"] == "/etc/ssl/client.key"
        assert cfg["ca_cert"] == "/etc/ssl/ca.pem"


class TestFileSecretsPermissionGuard:
    """`_load_file_config` should drop secrets if the file is group/world readable."""

    def _write(self, tmp_path, body, mode=0o600):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(body)
        cfg.chmod(mode)
        return cfg

    def _real_load(self, monkeypatch, cfg_path):
        """Bypass autouse-fixture stub and call the real loader.

        Order matters: undo() first (which reverts setenv too), then
        re-set PTY_CONFIG_FILE, then reload the module so the fresh
        `_load_file_config` is bound.
        """
        import importlib
        from appython.service import config as config_mod
        monkeypatch.undo()
        monkeypatch.setenv("PTY_CONFIG_FILE", str(cfg_path))
        importlib.reload(config_mod)
        return config_mod._load_file_config

    def test_secure_perms_secrets_kept(self, tmp_path, monkeypatch):
        cfg = self._write(
            tmp_path, "static_token: tok-xyz\nclient_secret: cs-xyz\n", mode=0o600
        )
        load = self._real_load(monkeypatch, cfg)
        out = load()
        assert out.get("static_token") == "tok-xyz"
        assert out.get("client_secret") == "cs-xyz"

    def test_loose_perms_secrets_dropped_others_kept(self, tmp_path, monkeypatch, capsys):
        import os as _os
        if _os.name == "nt":
            import pytest
            pytest.skip("POSIX-permission check is no-op on Windows")
        cfg = self._write(
            tmp_path,
            "protect_host: https://ok\nstatic_token: tok-xyz\nclient_secret: cs-xyz\n",
            mode=0o644,
        )
        load = self._real_load(monkeypatch, cfg)
        out = load()
        assert out.get("protect_host") == "https://ok"
        assert "static_token" not in out
        assert "client_secret" not in out
        err = capsys.readouterr().err
        assert "static_token" in err and "chmod 600" in err

    def test_loose_perms_no_secrets_no_warning(self, tmp_path, monkeypatch, capsys):
        import os as _os
        if _os.name == "nt":
            import pytest
            pytest.skip("POSIX-permission check is no-op on Windows")
        cfg = self._write(tmp_path, "protect_host: https://ok\n", mode=0o644)
        load = self._real_load(monkeypatch, cfg)
        out = load()
        assert out.get("protect_host") == "https://ok"
        assert "chmod" not in capsys.readouterr().err
