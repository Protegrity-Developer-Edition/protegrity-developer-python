"""
SDK configuration loader.

Resolution order (highest priority wins):
1. Environment variables (PTY_*, DEV_EDITION_*, AWS_*)
2. Config file (~/.protegrity/config.yaml or PTY_CONFIG_FILE path)
3. Built-in defaults
"""

import os
import stat
import sys
from pathlib import Path

_DEFAULTS = {
    "version": "1",
    "request_timeout": "30",
    "max_retries": "3",
}

# Legacy DE host
_DE_HOST = "api.developer-edition.protegrity.com"

# Keys that hold secrets-at-rest. Dropped from file_config if the file is
# group/world readable (POSIX). Mirrors `~/.pgpass` behavior.
_SECRET_FILE_KEYS = ("static_token", "client_secret")


def _file_is_secure(path):
    """True if `path` is readable only by the owner (mode & 077 == 0).

    On Windows we can't check POSIX bits, so we trust the filesystem ACL.
    """
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    if os.name == "nt":
        return True
    return (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0


def _load_file_config():
    """Load optional YAML config file. Returns empty dict if not found or yaml unavailable.

    Secret-bearing keys (see `_SECRET_FILE_KEYS`) are dropped with a stderr
    warning if the file is group/world readable. Non-secret keys are still
    returned so the rest of the SDK config keeps working.
    """
    config_path = os.getenv(
        "PTY_CONFIG_FILE", str(Path.home() / ".protegrity" / "config.yaml")
    )
    if not Path(config_path).is_file():
        return {}
    try:
        import yaml

        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
    except ImportError:
        return {}

    if not _file_is_secure(config_path):
        for k in _SECRET_FILE_KEYS:
            if k in cfg:
                print(
                    f"  ⚠ Refusing to read '{k}' from {config_path}: file is "
                    f"group/world readable. Run: chmod 600 {config_path}",
                    file=sys.stderr,
                )
                cfg.pop(k, None)
    return cfg


def _resolve(env_var, file_config, file_key, default=None):
    """Resolve a config value: env > file > default."""
    return os.getenv(env_var) or file_config.get(file_key) or _DEFAULTS.get(file_key) or default


def _detect_auth_mode():
    """Auto-detect auth mode from environment when PTY_AUTH_MODE is not set."""
    # If legacy DE vars are present, use cognito
    if os.getenv("DEV_EDITION_EMAIL") and os.getenv("DEV_EDITION_PASSWORD"):
        return "cognito"

    # If PTY_CP_HOST is set, try to detect further
    if os.getenv("PTY_CP_HOST"):
        # Check for AWS credentials
        if (
            os.getenv("AWS_ACCESS_KEY_ID")
            or os.getenv("AWS_PROFILE")
            or os.getenv("AWS_SESSION_TOKEN")
        ):
            return "aws_iam"

    return None


def _check_env_conflicts(file_config):
    """Raise early if environment variables indicate conflicting auth configurations."""
    explicit_mode = _resolve("PTY_AUTH_MODE", file_config, "auth_mode")
    has_de_vars = bool(os.getenv("DEV_EDITION_EMAIL") and os.getenv("DEV_EDITION_PASSWORD"))
    has_aws_creds = bool(
        os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE")
    )
    has_te_host = bool(os.getenv("PTY_CP_HOST") or file_config.get("protect_host"))

    # Conflict: PTY_AUTH_MODE=aws_iam but no PTY_CP_HOST
    if explicit_mode == "aws_iam" and not has_te_host:
        msg = (
            "PTY_AUTH_MODE=aws_iam but PTY_CP_HOST is not set. "
            "The SDK cannot use SigV4 without a Team Edition endpoint. "
        )
        if has_de_vars:
            msg += (
                "To use Developer Edition, unset: PTY_AUTH_MODE, AWS_ACCESS_KEY_ID, "
                "AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_PROFILE"
            )
        else:
            msg += "Set PTY_CP_HOST to your Team Edition endpoint."
        raise EnvironmentError(msg)

    # Warning: explicit aws_iam but DE vars also present (leftover from previous session)
    if explicit_mode == "aws_iam" and has_te_host and has_de_vars:
        import warnings
        warnings.warn(
            "PTY_AUTH_MODE=aws_iam but Developer Edition variables are also set "
            "(DEV_EDITION_*). These will be ignored. "
            "To silence this warning, unset: DEV_EDITION_EMAIL, "
            "DEV_EDITION_PASSWORD, DEV_EDITION_API_KEY.",
            stacklevel=2,
        )

    # Warning: explicit cognito but TE vars also present (leftover from previous session)
    if explicit_mode == "cognito" and has_aws_creds and has_te_host:
        import warnings
        warnings.warn(
            "PTY_AUTH_MODE=cognito but Team Edition variables are also set "
            "(PTY_CP_HOST, AWS credentials). These will be ignored. "
            "To silence this warning, unset: PTY_CP_HOST, AWS_ACCESS_KEY_ID, "
            "AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_PROFILE.",
            stacklevel=2,
        )

    # Conflict: both DE and TE credentials present without explicit mode
    if not explicit_mode and has_de_vars and has_aws_creds and has_te_host:
        raise EnvironmentError(
            "Conflicting credentials: both DEV_EDITION_* and AWS/PTY_CP_HOST variables are set. "
            "To use Team Edition, unset: DEV_EDITION_EMAIL, DEV_EDITION_PASSWORD, DEV_EDITION_API_KEY. "
            "To use Developer Edition, unset: PTY_CP_HOST, AWS_ACCESS_KEY_ID, "
            "AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_PROFILE."
        )


def load_config():
    """Load SDK configuration with resolution order: env > file > defaults.

    Returns:
        dict: Resolved configuration dictionary.

    Raises:
        EnvironmentError: If conflicting credential variables are detected.
    """
    file_config = _load_file_config()

    # Detect conflicting environment variables early
    _check_env_conflicts(file_config)

    auth_mode = _resolve("PTY_AUTH_MODE", file_config, "auth_mode")
    if not auth_mode:
        auth_mode = _detect_auth_mode()

    protect_host = _resolve("PTY_CP_HOST", file_config, "protect_host")

    # Backward compat: if no PTY_CP_HOST but DE vars exist, build from DE host
    if not protect_host and auth_mode == "cognito":
        runtime_host = os.getenv("DEV_EDITION_HOST", _DE_HOST)
        protect_host = f"https://{runtime_host}"

    return {
        "protect_host": protect_host,
        "auth_mode": auth_mode,
        "version": _resolve("PTY_API_VERSION", file_config, "version", "1"),
        "request_timeout": int(
            _resolve("PTY_REQUEST_TIMEOUT", file_config, "request_timeout", "30")
        ),
        "max_retries": int(
            _resolve("PTY_MAX_RETRIES", file_config, "max_retries", "3")
        ),
        # Bearer token mode
        "token_endpoint": _resolve("PTY_TOKEN_ENDPOINT", file_config, "token_endpoint"),
        "client_id": _resolve("PTY_CLIENT_ID", file_config, "client_id"),
        "client_secret": _resolve("PTY_CLIENT_SECRET", file_config, "client_secret"),
        "static_token": _resolve("PTY_STATIC_TOKEN", file_config, "static_token"),
        # mTLS mode
        "client_cert": _resolve("PTY_CLIENT_CERT", file_config, "client_cert"),
        "client_key": _resolve("PTY_CLIENT_KEY", file_config, "client_key"),
        "ca_cert": _resolve("PTY_CA_CERT", file_config, "ca_cert"),
        # pty-migrate CLI settings (PPC admin endpoint; passwords stay env-only)
        "ppc_host": _resolve("PTY_PPC_HOST", file_config, "ppc_host"),
        "ppc_user": _resolve("PTY_PPC_USER", file_config, "ppc_user"),
        "ppc_port": _resolve("PTY_PPC_PORT", file_config, "ppc_port"),
        "workbench_user": _resolve("PTY_WORKBENCH_USER", file_config, "workbench_user"),
        "stats_file": _resolve("PTY_STATS_FILE", file_config, "stats_file"),
        # Legacy DE vars (for cognito provider)
        "de_email": os.getenv("DEV_EDITION_EMAIL"),
        "de_password": os.getenv("DEV_EDITION_PASSWORD"),
        "de_api_key": os.getenv("DEV_EDITION_API_KEY"),
    }
