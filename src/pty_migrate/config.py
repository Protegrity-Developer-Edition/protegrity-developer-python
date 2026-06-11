"""Config resolution for pty-migrate CLI.

Precedence (highest wins):
  1. CLI flag (explicit on command line)
  2. Environment variable
  3. ~/.protegrity/config.yaml (or $PTY_CONFIG_FILE)
  4. Built-in default

Password handling
-----------------
Passwords (`ppc_password`, `workbench_password`) are NOT read from the YAML
file by default. To opt in, the user must set both:

    allow_secrets_in_file: true

at the top of the YAML AND the file must be `chmod 600` (or stricter). If the
file is group/world-readable the secrets are dropped and a warning is printed
to stderr, even when the opt-in is set.

This mirrors `~/.pgpass` behavior: secrets-at-rest are allowed, but the tool
refuses to read them from a permissive file.
"""

import os
import stat
import sys
from functools import lru_cache
from pathlib import Path


_PASSWORD_KEYS = ("ppc_password", "workbench_password")


def _config_path():
    return os.getenv(
        "PTY_CONFIG_FILE", str(Path.home() / ".protegrity" / "config.yaml")
    )


def _file_is_secure(path):
    """True if `path` is readable only by the owner (mode & 077 == 0)."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    if os.name == "nt":
        # Windows doesn't use POSIX bits — assume secure (ACL-based, out of scope).
        return True
    return (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0


@lru_cache(maxsize=1)
def _file_cfg():
    """Load the SDK config file once per process, applying secret-perm rules.

    Returns {} on any failure. Password keys are stripped (with a stderr
    warning) unless `allow_secrets_in_file: true` AND the file is `chmod 600`.
    """
    try:
        from appython.service.config import _load_file_config
        cfg = _load_file_config() or {}
    except Exception:
        return {}

    has_password_keys = any(k in cfg for k in _PASSWORD_KEYS)
    if not has_password_keys:
        return cfg

    path = _config_path()
    allow = bool(cfg.get("allow_secrets_in_file"))
    if not allow:
        for k in _PASSWORD_KEYS:
            if k in cfg:
                print(
                    f"  ⚠ Ignoring '{k}' in {path}: set 'allow_secrets_in_file: true' "
                    f"to enable file-based passwords.",
                    file=sys.stderr,
                )
                cfg.pop(k, None)
        return cfg

    if not _file_is_secure(path):
        for k in _PASSWORD_KEYS:
            if k in cfg:
                print(
                    f"  ⚠ Refusing to read '{k}' from {path}: file is group/world readable. "
                    f"Run: chmod 600 {path}",
                    file=sys.stderr,
                )
                cfg.pop(k, None)
    return cfg


def resolve(cli_value, env_var, file_key, default=None):
    """Resolve a single setting using CLI > env > file > default."""
    if cli_value is not None and cli_value != "":
        return cli_value
    env_val = os.getenv(env_var) if env_var else None
    if env_val:
        return env_val
    file_val = _file_cfg().get(file_key) if file_key else None
    if file_val is not None and file_val != "":
        return file_val
    return default


def resolve_password(cli_value, env_var, file_key):
    """Resolve a password: CLI > env > file (only if opt-in + chmod 600).

    Returns a tuple (value, source) where source is one of:
        "cli", "env", "file", None
    """
    if cli_value:
        return cli_value, "cli"
    env_val = os.getenv(env_var) if env_var else None
    if env_val:
        return env_val, "env"
    file_val = _file_cfg().get(file_key) if file_key else None
    if file_val:
        return file_val, "file"
    return None, None


def file_has(file_key):
    """True if `file_key` is set in the YAML config (used for 'explicit' detection)."""
    val = _file_cfg().get(file_key)
    return val is not None and val != ""
