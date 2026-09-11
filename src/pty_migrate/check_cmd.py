"""pty-migrate check command — pre-flight migration readiness validation."""

import json
import os
import sys
from pathlib import Path

# Default data elements from the Developer Edition README examples
_DEFAULT_DATA_ELEMENTS = ["name", "ssn", "email", "city", "phone"]
_DEFAULT_POLICY_USER = "superuser"

_PAYLOADS_DIR = Path(__file__).parent / "payloads"

_NOT_INSTALLED = "not installed"
_LABEL_PPC_DATASTORES = "PPC datastores"
_LABEL_PPC_DATA_ELEMENTS = "PPC data elements"
_LABEL_PPC_ROLE_MEMBERS = "PPC role members"
_LABEL_PPC_DATASTORE_EXPORT_KEYS = "PPC datastore export keys"


def _load_rules_index():
    """Build a lookup of expected permissions from the bundled DE payloads.

    Returns a dict with:
        user_to_role: {username: role_id_str}
        de_name_to_id: {de_name: de_id_str}
        rules: {(role_id_str, de_id_str): {"protect": bool, "unProtect": bool}}
    Returns None if any payload is missing/unreadable.
    """
    try:
        with open(_PAYLOADS_DIR / "members.json") as f:
            members = json.load(f)
        with open(_PAYLOADS_DIR / "dataelements.json") as f:
            des = json.load(f)
        with open(_PAYLOADS_DIR / "rules.json") as f:
            rules_raw = json.load(f)
    except Exception:
        return None

    user_to_role = {}
    for key, member_list in members.items():
        # key like "roles/2/members"
        parts = key.split("/")
        if len(parts) >= 2:
            rid = parts[1]
            for m in member_list:
                name = m.get("name")
                if name:
                    user_to_role[name] = rid

    de_name_to_id = {de.get("name"): str(i + 1) for i, de in enumerate(des) if de.get("name")}

    rules = {}
    for r in rules_raw:
        role = str(r.get("role"))
        de = str(r.get("dataElement"))
        access = r.get("permission", {}).get("access", {})
        rules[(role, de)] = {
            "protect": bool(access.get("protect")),
            "unProtect": bool(access.get("unProtect")),
        }

    return {"user_to_role": user_to_role, "de_name_to_id": de_name_to_id, "rules": rules}


def _expected_round_trip(rules_index, user, de_name):
    """Return True if (user, de) is expected to round-trip per bundled rules.

    Returns None if user or DE is unknown to the bundled payloads."""
    if not rules_index:
        return None
    rid = rules_index["user_to_role"].get(user)
    did = rules_index["de_name_to_id"].get(de_name)
    if not rid or not did:
        return None
    rule = rules_index["rules"].get((rid, did))
    if not rule:
        return False  # no rule = no access
    return rule["protect"] and rule["unProtect"]


def _expected_can_protect(rules_index, user, de_name):
    """Return True if (user, de) is expected to be able to protect per rules."""
    if not rules_index:
        return None
    rid = rules_index["user_to_role"].get(user)
    did = rules_index["de_name_to_id"].get(de_name)
    if not rid or not did:
        return None
    rule = rules_index["rules"].get((rid, did))
    if not rule:
        return False
    return rule["protect"]


def _load_stats(stats_file=None):
    """Load usage stats from file."""
    from pty_migrate.config import resolve
    resolved = resolve(stats_file, "PTY_STATS_FILE", "stats_file",
                       str(Path.home() / ".protegrity" / "usage_stats.json"))
    path = Path(resolved)
    if not path.is_file():
        return None
    with open(path, "r") as f:
        return json.load(f)


def _check_sdk_version():
    """Check Python SDK version >= 1.2.1.

    Returns (status, detail) where status is one of:
      "ok"         — installed and >= 1.2.1
      "old"        — installed but < 1.2.1
      "load_error" — package metadata says installed but `import appython` fails
                     (e.g. Windows: SDK uses fcntl which is unix-only)
      "missing"    — package not installed at all
    """
    # Prefer package metadata so we can tell "not installed" apart from
    # "installed but unimportable on this OS".
    try:
        from importlib.metadata import version as _pkg_version, PackageNotFoundError as _PackageNotFoundError
    except ImportError:  # pragma: no cover  (py<3.8)
        _pkg_version = None
        _PackageNotFoundError = Exception  # type: ignore

    pkg_ver = None
    if _pkg_version is not None:
        try:
            pkg_ver = _pkg_version("protegrity-ai-developer-python")
        except _PackageNotFoundError:
            pkg_ver = None

    try:
        from appython import Protector
        protector = Protector()
        version = protector.get_version()
        parts = version.split(".")
        major, minor = int(parts[0]), int(parts[1])
        ok = (major > 1) or (major == 1 and minor >= 2)
        return ("ok" if ok else "old"), version
    except Exception as e:
        if pkg_ver is not None:
            return "load_error", f"{pkg_ver} installed but failed to load: {e}"
        return "missing", _NOT_INSTALLED


def _check_java_sdk_version():
    """Check Java SDK version >= 1.1.0 from local Maven repo."""
    m2_path = Path.home() / ".m2" / "repository" / "com" / "protegrity" / "application-protector-java"
    if not m2_path.is_dir():
        return None, _NOT_INSTALLED

    versions = []
    for d in m2_path.iterdir():
        if d.is_dir() and d.name[0].isdigit():
            versions.append(d.name)
    if not versions:
        return None, "not installed"

    # Find highest version
    def version_tuple(v):
        try:
            return tuple(int(x) for x in v.split("."))
        except ValueError:
            return (0,)

    versions.sort(key=version_tuple, reverse=True)
    latest = versions[0]
    parts = version_tuple(latest)
    ok = parts >= (1, 1, 0)
    return ok, latest


def _sdk_cfg():
    """Load SDK config (env > YAML > defaults). Returns {} on failure."""
    try:
        from appython.service.config import load_config
        return load_config() or {}
    except Exception:
        return {}


def _check_te_host():
    """Check Cloud Protect host is configured (env PTY_CP_HOST or YAML protect_host)."""
    host = _sdk_cfg().get("protect_host") or ""
    return bool(host), host


def _check_auth_mode():
    """Check auth mode is configured (env PTY_AUTH_MODE or YAML auth_mode) with required credentials."""
    cfg = _sdk_cfg()
    mode = cfg.get("auth_mode") or ""
    if not mode:
        return False, "", "PTY_AUTH_MODE not set"

    detail = ""
    if mode == "aws_iam":
        profile = os.getenv("AWS_PROFILE", "")
        if profile:
            detail = f"profile: {profile}"
        elif os.getenv("AWS_ACCESS_KEY_ID"):
            detail = "env credentials"
            if os.getenv("AWS_SESSION_TOKEN"):
                detail += " (with session token)"
        else:
            return False, mode, "No AWS credentials found (set AWS_PROFILE or AWS_ACCESS_KEY_ID)"
    elif mode == "bearer_token":
        # Matches BearerTokenAuthProvider.initialize(): either a static token, or
        # the OAuth2 client_credentials triplet (token endpoint + client id + secret).
        if cfg.get("static_token"):
            detail = "static token present"
        elif cfg.get("token_endpoint") and cfg.get("client_id") and cfg.get("client_secret"):
            detail = "oauth2 client_credentials configured"
        else:
            return (
                False,
                mode,
                "set PTY_STATIC_TOKEN, or PTY_TOKEN_ENDPOINT + PTY_CLIENT_ID + PTY_CLIENT_SECRET",
            )
    elif mode == "mtls":
        cert = cfg.get("client_cert") or ""
        key = cfg.get("client_key") or ""
        if not cert or not key:
            return False, mode, "PTY_CLIENT_CERT and PTY_CLIENT_KEY required"
        detail = f"cert: {cert}"
    elif mode == "cognito":
        detail = "Developer Edition mode (not TE)"
    elif mode == "none":
        detail = "no auth"

    return True, mode, detail


def _shell_export(var, value):
    """Render a shell `set/export` line appropriate for the current platform."""
    if os.name == "nt":
        # PowerShell — what `pty-migrate` users on Windows almost always have
        return f"$env:{var} = \"{value}\""
    return f"export {var}={value}"


def _auth_fix_hints(mode, detail, indent="    → ", continuation=None):
    """Return a list of resolution lines tailored to the actual auth failure.

    `mode` is the value of PTY_AUTH_MODE we observed (may be "" if unset).
    `detail` is the failure message from `_check_auth_mode` — we use it to
    distinguish "no mode set" from "mode set but missing credentials".
    """
    cont = continuation if continuation is not None else " " * len(indent)
    lines = []

    if not mode:
        lines.append(f"{indent}Pick an auth mode and set its credentials. Most common:")
        lines.append(f"{cont}  {_shell_export('PTY_AUTH_MODE', 'aws_iam')}  "
                     f"# Cloud Protect behind AWS API Gateway")
        lines.append(f"{cont}  {_shell_export('PTY_AUTH_MODE', 'bearer_token')}  "
                     f"# static JWT or OAuth2 client_credentials")
        return lines

    if mode == "aws_iam":
        lines.append(f"{indent}aws_iam mode needs AWS credentials. Either:")
        lines.append(f"{cont}  {_shell_export('AWS_PROFILE', '<profile-name>')}  "
                     f"# uses ~/.aws/credentials")
        lines.append(f"{cont}  or set the three env vars directly:")
        lines.append(f"{cont}    {_shell_export('AWS_ACCESS_KEY_ID', '<key>')}")
        lines.append(f"{cont}    {_shell_export('AWS_SECRET_ACCESS_KEY', '<secret>')}")
        lines.append(f"{cont}    {_shell_export('AWS_SESSION_TOKEN', '<session-token>')}  "
                     f"# required for STS / SSO / temporary credentials")
        lines.append(f"{cont}  {_shell_export('AWS_DEFAULT_REGION', 'us-east-1')}  "
                     f"# region of your Cloud Protect deployment")
    elif mode == "bearer_token":
        lines.append(f"{indent}bearer_token mode needs either a static token or OAuth2 creds:")
        lines.append(f"{cont}  {_shell_export('PTY_STATIC_TOKEN', '<jwt>')}")
        lines.append(f"{cont}  or: {_shell_export('PTY_TOKEN_ENDPOINT', '<url>')}, "
                     f"PTY_CLIENT_ID, PTY_CLIENT_SECRET")
    elif mode == "oauth2_client_credentials":
        lines.append(f"{indent}oauth2_client_credentials needs three vars:")
        lines.append(f"{cont}  {_shell_export('PTY_TOKEN_ENDPOINT', '<url>')}")
        lines.append(f"{cont}  {_shell_export('PTY_CLIENT_ID', '<id>')}")
        lines.append(f"{cont}  {_shell_export('PTY_CLIENT_SECRET', '<secret>')}")
    elif mode == "mtls":
        lines.append(f"{indent}mtls mode needs client cert + key:")
        lines.append(f"{cont}  {_shell_export('PTY_CLIENT_CERT', '/path/to/client.crt')}")
        lines.append(f"{cont}  {_shell_export('PTY_CLIENT_KEY', '/path/to/client.key')}")
    else:
        lines.append(f"{indent}{detail}")
    return lines


def _check_endpoint_reachable(host):
    """Check if TE endpoint is reachable."""
    import requests
    try:
        # Try a lightweight request
        resp = requests.get(f"{host}/v1/version", timeout=10, verify=True)
        if resp.status_code in (200, 401, 403):
            return True, f"HTTP {resp.status_code}"
        return True, f"HTTP {resp.status_code}"
    except requests.exceptions.SSLError:
        # Try without SSL verification
        try:
            resp = requests.get(f"{host}/v1/version", timeout=10, verify=False)  # NOSONAR
            return True, "reachable (SSL warning)"
        except Exception:
            pass
    except requests.exceptions.ConnectionError:
        return False, "Connection refused"
    except requests.exceptions.Timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
    return False, "Unreachable"


def _check_auth_works():
    """Attempt an authenticated request to TE/Cloud Protect."""
    try:
        from appython import Protector

        protector = Protector()
        session = protector.create_session("superuser")
        # Attempt a protect call — if auth works this will either succeed
        # or fail with a policy error (not auth error)
        try:
            session.protect("auth_check_probe", "name")
            return True, "authenticated (protect succeeded)"
        except Exception as e:
            err = str(e).lower()
            # Auth/connection errors
            if "401" in err or "403" in err or "unauthorized" in err or "forbidden" in err:
                return False, f"credentials rejected — {e}"
            if "connection" in err or "timeout" in err or "unreachable" in err:
                return False, f"connection failed — {e}"
            # Any other error (e.g. DE not found, policy error) means auth worked
            return True, "authenticated (endpoint responded)"
    except Exception as e:
        return False, str(e)


def _check_data_elements(stats):
    """Verify the policy is reachable end-to-end via a single protect call.

    A successful `protect` proves three things at once: the SDK is configured,
    Cloud Protect is reachable, and the policy/DE is deployed. There is no
    value in running this for every DE × user combination — it just multiplies
    latency and retry storms when something is wrong.

    Strategy: pick one DE and one user, prefer those the bundled rules say
    can both protect AND unProtect (so we can also verify round-trip), then
    fall back to any DE the user used in the local stats.
    """
    rules_index = _load_rules_index()

    # Choose a DE — prefer something the user actually used locally and that
    # is also part of the standard bundled policy; fall back to `name`.
    stats_des = list(stats.get("data_elements", {}).keys()) if stats else []
    bundled_set = set(_bundled_de_names())
    candidate_des = [de for de in stats_des if de in bundled_set] or ["name"]

    # Choose a user — prefer one bundled into the standard policy.
    bundled_users = _bundled_member_names()
    stats_users = list(stats.get("policy_users", {}).keys()) if stats else []
    candidate_users = [u for u in stats_users if u in bundled_users] or [_DEFAULT_POLICY_USER]

    # Pick the (de, user) pair that supports the strongest test (round-trip).
    chosen_de = None
    chosen_user = None
    can_round_trip = False
    if rules_index:
        for de in candidate_des:
            for user in candidate_users:
                if (_expected_can_protect(rules_index, user, de) is True
                        and _expected_round_trip(rules_index, user, de) is True):
                    chosen_de, chosen_user, can_round_trip = de, user, True
                    break
            if chosen_de:
                break
        if not chosen_de:
            for de in candidate_des:
                for user in candidate_users:
                    if _expected_can_protect(rules_index, user, de) is True:
                        chosen_de, chosen_user = de, user
                        break
                if chosen_de:
                    break
    if not chosen_de:
        chosen_de = candidate_des[0]
        chosen_user = candidate_users[0]

    plaintext = "test_migration_check"
    try:
        from appython import Protector
        protector = Protector()
        session = protector.create_session(chosen_user)
        try:
            protected = session.protect(plaintext, chosen_de)
        except Exception as e:
            return False, f"protect failed (user={chosen_user}, de={chosen_de}): {e}"

        if not can_round_trip:
            return True, (f"protect OK (user={chosen_user}, de={chosen_de}) "
                          f"— round-trip not attempted (user lacks unProtect on this DE)")

        try:
            unprotected = session.unprotect(protected, chosen_de)
        except Exception as e:
            return False, f"unprotect failed (user={chosen_user}, de={chosen_de}): {e}"

        if unprotected == plaintext:
            return True, f"round-trip OK (user={chosen_user}, de={chosen_de})"
        if unprotected == protected:
            return True, (f"protect OK (user={chosen_user}, de={chosen_de}) "
                          f"— unprotect returned the protected value (PROTECTED_VALUE policy)")
        return False, f"unprotect mismatch (user={chosen_user}, de={chosen_de}): got {unprotected!r}"
    except Exception as e:
        return False, str(e)


def _bundled_de_names():
    """Return all DE names from the bundled Developer Edition payloads."""
    try:
        with open(_PAYLOADS_DIR / "dataelements.json") as f:
            des = json.load(f)
        return [d.get("name") for d in des if d.get("name")]
    except Exception:
        return []


def _bundled_member_names():
    """Return all policy-user names from the bundled members payload.

    These are the only users that `pty-migrate create-policy` will register
    on PPC, so they are the only ones worth checking for. Anything in the
    stats file that is not in this set is test/sandbox data the user wrote
    on their own and not part of the standard Developer Edition policy.
    """
    try:
        with open(_PAYLOADS_DIR / "members.json") as f:
            groups = json.load(f)
        names = set()
        for members in groups.values():
            for m in members or []:
                name = m.get("name")
                if name:
                    names.add(name)
        return names
    except Exception:
        return set()


def _check_ppc_deployment(ppc, stats, full=False):
    """Verify PPC deployment state: DEs, roles+members, datastore export key.

    Args:
        ppc: dict with 'host', 'user', 'password' (resolved from args + env).
        stats: parsed usage stats (may be None).
        full: when True, verify all bundled DE names instead of only those in stats.

    Returns (results, info) where:
        results: list of (label, ok, detail) tuples for each sub-check.
        info: dict with side-channel data the caller needs for resolution
              hints (currently: dev_edition_uid).
    """
    results = []
    info = {"dev_edition_uid": None}
    try:
        from pty_migrate.ppc_client import PPCClient
        client = PPCClient(ppc["host"], ppc["user"], ppc["password"])
        client.authenticate()
    except Exception as e:
        return [("PPC connection", False, f"failed to connect/authenticate: {e}")], info

    # Datastores — DevEdition expected
    try:
        datastores = client.list_datastores()
    except Exception as e:
        return [(_LABEL_PPC_DATASTORES, False, str(e))], info
    if not datastores:
        results.append((_LABEL_PPC_DATASTORES, False, "no datastores defined"))
        return results, info
    ds_names = [d.get("name", "?") for d in datastores]
    dev_edition_ds = next((d for d in datastores if d.get("name") == "DevEdition"), None)
    if dev_edition_ds:
        info["dev_edition_uid"] = dev_edition_ds.get("uid") or dev_edition_ds.get("id")
        results.append((_LABEL_PPC_DATASTORES, True,
                        f"DevEdition present (id={info['dev_edition_uid']}, "
                        f"{len(datastores)} total: {', '.join(ds_names)})"))
    else:
        results.append((_LABEL_PPC_DATASTORES, False,
                        f"DevEdition datastore not found (have: {', '.join(ds_names)})"))

    # Data elements present on PPC
    bundled_de_set = set(_bundled_de_names())
    if full:
        required_des = list(bundled_de_set) or _DEFAULT_DATA_ELEMENTS
        scope_note = "all bundled Developer Edition DEs"
        skipped_des = []
    else:
        stats_des = list(stats.get("data_elements", {}).keys()) if stats else []
        if not stats_des:
            required_des = list(_DEFAULT_DATA_ELEMENTS)
            skipped_des = []
        elif bundled_de_set:
            # Only check DEs that are part of the standard DE policy. Anything
            # else in stats (e.g. `pii_test`, `dob`) is user/test data the
            # migration tool does not create and cannot verify.
            required_des = [de for de in stats_des if de in bundled_de_set]
            skipped_des = [de for de in stats_des if de not in bundled_de_set]
        else:
            required_des = stats_des
            skipped_des = []
        scope_note = "standard DEs from local stats"
    try:
        ppc_des = client.list_data_elements()
    except Exception as e:
        return results + [(_LABEL_PPC_DATA_ELEMENTS, False, str(e))], info
    ppc_de_names = {d.get("name") for d in ppc_des}
    missing_des = [de for de in required_des if de not in ppc_de_names]
    skipped_suffix = (
        f" (ignored {len(skipped_des)} non-standard: {', '.join(skipped_des)})"
        if skipped_des else ""
    )
    if missing_des:
        results.append((_LABEL_PPC_DATA_ELEMENTS, False,
                        f"{len(missing_des)} of {len(required_des)} {scope_note} missing: "
                        f"{', '.join(missing_des)}{skipped_suffix}"))
    elif not required_des:
        results.append((_LABEL_PPC_DATA_ELEMENTS, None,
                        f"no standard DEs to check{skipped_suffix}"))
    else:
        results.append((_LABEL_PPC_DATA_ELEMENTS, True,
                        f"all {len(required_des)} {scope_note} present{skipped_suffix}"))

    # Policy users registered as role members on PPC
    bundled_users = _bundled_member_names()
    stats_users = list(stats.get("policy_users", {}).keys()) if stats else []
    if bundled_users:
        required_users = [u for u in stats_users if u in bundled_users]
        skipped_users = [u for u in stats_users if u not in bundled_users]
    else:
        required_users = stats_users
        skipped_users = []
    user_skipped_suffix = (
        f" (ignored {len(skipped_users)} non-standard: {', '.join(skipped_users)})"
        if skipped_users else ""
    )
    if required_users:
        try:
            roles = client.list_roles()
            all_members = set()
            for role in roles:
                rid = role.get("uid") or role.get("id")
                if not rid:
                    continue
                try:
                    members = client.list_role_members(rid)
                    for m in members:
                        name = m.get("memberName") or m.get("name") or m.get("username")
                        if name:
                            all_members.add(name)
                except Exception:
                    continue
            missing_users = [u for u in required_users if u not in all_members]
            if missing_users:
                results.append((_LABEL_PPC_ROLE_MEMBERS, False,
                                f"users not in any role: {', '.join(missing_users)}"
                                f"{user_skipped_suffix}"))
            else:
                results.append((_LABEL_PPC_ROLE_MEMBERS, True,
                                f"all {len(required_users)} users are role members"
                                f"{user_skipped_suffix}"))
        except Exception as e:
            results.append((_LABEL_PPC_ROLE_MEMBERS, False, str(e)))
    else:
        results.append((_LABEL_PPC_ROLE_MEMBERS, None,
                        f"no standard policy users in stats{user_skipped_suffix}"))

    # Datastore export keys (required for Cloud Protect to publish the policy)
    ds_with_keys = []
    ds_without_keys = []
    for ds in datastores:
        ds_uid = ds.get("uid") or ds.get("id")
        if not ds_uid:
            continue
        try:
            keys = client.list_export_keys(ds_uid)
            if keys:
                ds_with_keys.append(ds.get("name", ds_uid))
            else:
                ds_without_keys.append(ds.get("name", ds_uid))
        except Exception:
            ds_without_keys.append(ds.get("name", ds_uid))
    if "DevEdition" in ds_with_keys:
        results.append((_LABEL_PPC_DATASTORE_EXPORT_KEYS, True,
                        f"configured on DevEdition (and: {', '.join(ds_with_keys)})"))
    elif ds_with_keys:
        results.append((_LABEL_PPC_DATASTORE_EXPORT_KEYS, False,
                        f"export keys present on {', '.join(ds_with_keys)} "
                        f"but not on DevEdition"))
    else:
        results.append((_LABEL_PPC_DATASTORE_EXPORT_KEYS, False,
                        f"no export keys on any datastore ({', '.join(ds_without_keys)})"))

    return results, info


def _resolve_ppc_args(args):
    """Resolve PPC connection args using CLI > env > config file > default.

    Returns a dict {host, user, password} with any value possibly None.
    Passwords are file-readable only with `allow_secrets_in_file: true`
    AND chmod 600 on the config file (see pty_migrate.config).
    """
    from pty_migrate.config import resolve, resolve_password
    password, pw_source = resolve_password(
        getattr(args, "ppc_password", None), "PTY_PPC_PASSWORD", "ppc_password"
    )
    if pw_source == "file":
        print("  · PPC password loaded from ~/.protegrity/config.yaml (chmod 600 verified).")
    return {
        "host": resolve(getattr(args, "ppc_host", None), "PTY_PPC_HOST", "ppc_host"),
        "user": resolve(getattr(args, "ppc_user", None), "PTY_PPC_USER", "ppc_user", "workbench"),
        "password": password,
    }


def run_check(args):
    """Execute the check command."""
    stats = _load_stats(args.stats_file)
    ppc = _resolve_ppc_args(args)
    with_protect_test = getattr(args, "with_protect_fn_test", False)
    ppc_creds_present = bool(ppc["host"] and ppc["password"])

    # Mode resolution: PPC verification is the default; --with-protect-fn-test
    # opts into the round-trip path. Both can run together.
    do_ppc = ppc_creds_present
    do_protect_test = with_protect_test
    if not do_ppc and not do_protect_test:
        print()
        print("  ✗ PPC credentials required.")
        print("    Set PTY_PPC_HOST and PTY_PPC_PASSWORD environment variables, or pass")
        print("    --ppc-host and --ppc-password.")
        print("    Alternatively, pass --with-protect-fn-test to run a protect/unprotect")
        print("    smoke check against Cloud Protect (no PPC required).")
        print()
        return 1

    title = "Protegrity Developer → Team Edition Migration Readiness Check"
    print()
    print(f"  {title}")
    print(f"  {'─' * len(title)}")
    print()

    issues = 0

    # 1. SDK versions
    py_status, py_version = _check_sdk_version()
    java_ok, java_version = _check_java_sdk_version()
    py_ok = py_status == "ok"

    if py_ok:
        print(f"  ✓ Python SDK: {py_version} (minimum: 1.2.1)")
    elif py_status == "old":
        print(f"  ✗ Python SDK: {py_version} (need >= 1.2.1)")
        print("    → pip install --upgrade protegrity-ai-developer-python")
    elif py_status == "load_error":
        # Package installed but `import appython` raised. Report verbatim so
        # users can act on the underlying ImportError without us guessing.
        print(f"  ✗ Python SDK: {py_version}")
        print("    → Reinstall the SDK: pip install --force-reinstall protegrity-ai-developer-python")
    else:  # missing
        print("  · Python SDK: not installed")

    if java_ok is True:
        print(f"  ✓ Java SDK: {java_version} (minimum: 1.1.0)")
    elif java_ok is False:
        print(f"  ✗ Java SDK: {java_version} (need >= 1.1.0)")
        print("    → Update the Java SDK dependency in your pom.xml to >= 1.1.0")
    else:
        print("  · Java SDK: not installed")

    # Migration only needs one SDK at the required version.
    sdk_ok = py_ok or (java_ok is True)
    if not sdk_ok:
        # Don't repeat per-SDK fix hints already printed above. Only add the
        # "install at least one" message when neither is present at all.
        if py_status == "missing" and java_ok is None:
            print("    → Install at least one SDK:")
            print("      Python: pip install --upgrade protegrity-ai-developer-python")
            print("      Java:   add com.protegrity:application-protector-java >= 1.1.0 to pom.xml")
        issues += 1

    # 2. Team Edition host configured
    ok, host = _check_te_host()
    if ok:
        print(f"  ✓ PTY_CP_HOST: {host}")
    else:
        print("  ✗ PTY_CP_HOST not set")
        print("    → export PTY_CP_HOST=<your-cloud-protect-invoke-url>")
        issues += 1

    # 3. Auth mode configured
    auth_ok, mode, detail = _check_auth_mode()
    if auth_ok:
        print(f"  ✓ PTY_AUTH_MODE: {mode} ({detail})")
    else:
        print(f"  ✗ {detail}")
        for line in _auth_fix_hints(mode, detail, indent="    → "):
            print(line)
        issues += 1

    # 4. Team Edition endpoint reachable
    if ok and host:
        reachable, reach_detail = _check_endpoint_reachable(host)
        if reachable:
            print(f"  ✓ Team Edition endpoint reachable ({reach_detail})")
        else:
            print(f"  ✗ Team Edition endpoint unreachable: {reach_detail}")
            issues += 1
    else:
        print("  ⊘ Team Edition endpoint: skipped (no host configured)")

    # 5. Authentication works (only needed for protect-fn test)
    auth_works = None
    if do_protect_test and ok and host and auth_ok:
        auth_works, auth_detail = _check_auth_works()
        if auth_works:
            print(f"  ✓ Authentication: {auth_detail}")
        else:
            print(f"  ✗ Authentication failed: {auth_detail}")
            print("    → Verify your credentials and that the policy is deployed on your PPC")
            print("    → Run: pty-migrate create-policy --ppc-host <your-ppc-host> --ppc-password <password>")
            issues += 1
    elif do_protect_test:
        print("  ⊘ Authentication: skipped (prerequisites not met)")

    # 6. Policy users
    if stats:
        users = list(stats.get("policy_users", {}).keys())
        if users:
            print(f"  ✓ Policy users (from stats): {', '.join(users)}")
        else:
            print(f"  · No policy users in stats — using default: {_DEFAULT_POLICY_USER}")
    else:
        print(f"  · No stats file — using default user: {_DEFAULT_POLICY_USER}")

    de_failed = False
    ppc_failed = False

    # 7a. PPC deployment verification (default mode)
    if do_ppc:
        scope = "all bundled Developer Edition data elements" if getattr(args, "full", False) \
            else "data elements from local stats"
        print(f"  · PPC deployment verification ({ppc['host']}, scope: {scope}):")
        ppc_results, ppc_info = _check_ppc_deployment(ppc, stats, full=getattr(args, "full", False))
        dev_edition_uid = ppc_info.get("dev_edition_uid")
        for label, ppc_ok, detail in ppc_results:
            if ppc_ok is True:
                print(f"  ✓ {label}: {detail}")
            elif ppc_ok is False:
                print(f"  ✗ {label}: {detail}")
                ppc_failed = True
                issues += 1
            else:
                print(f"  · {label}: {detail}")
        if ppc_failed:
            print(f"    → Run: pty-migrate create-policy --ppc-host {ppc['host']} --ppc-password <password>")
            print("      (add --full to create the full Developer Edition policy)")
            if dev_edition_uid:
                print(f"    → Ensure the DevEdition datastore (id={dev_edition_uid}) has the KMS export key configured.")
            else:
                print("    → Ensure the DevEdition datastore has the KMS export key configured.")

    # 7b. Round-trip protect/unprotect test (--with-protect-fn-test)
    if do_protect_test:
        if ok and host and auth_ok and auth_works:
            de_ok, de_detail = _check_data_elements(stats)
            if de_ok is True:
                print(f"  ✓ Protect/unprotect test: {de_detail}")
            elif de_ok is False:
                print(f"  ✗ Protect/unprotect test: {de_detail}")
                de_failed = True
                issues += 1
            else:
                print(f"  ⊘ Protect/unprotect test: {de_detail}")
        elif auth_works is False:
            # Auth probe already failed — skip the full sweep so we don't
            # hang for minutes hammering 28 DEs × N users with bad creds.
            print("  ⊘ Protect/unprotect test: skipped (authentication failed)")
        else:
            print("  ⊘ Protect/unprotect test: skipped (prerequisites not met)")

    # Result
    print()
    print(f"  {'─' * 50}")
    if issues == 0:
        print("  RESULT: ✓ READY FOR MIGRATION")
        print()
        print("  Next steps:")
        step = 1
        if do_ppc and not do_protect_test:
            print(f"    {step}. Trigger the Policy Agent Lambda so the policy is published to Cloud Protect")
            print("       (runs hourly if CRON enabled, or invoke manually from the AWS Lambda console).")
            step += 1
            print(f"    {step}. Re-run `pty-migrate check --with-protect-fn-test` to verify end-to-end.")
            step += 1
        de_vars_set = [v for v in (
            "DEV_EDITION_EMAIL", "DEV_EDITION_PASSWORD", "DEV_EDITION_API_KEY",
            "DEV_EDITION_HOST", "DEV_EDITION_VERSION",
        ) if os.getenv(v)]
        if de_vars_set:
            print(f"    {step}. Remove leftover Developer Edition env vars: {', '.join(de_vars_set)}")
            step += 1
        print(f"    {step}. Your application will now use Team Edition automatically.")
    else:
        print(f"  RESULT: ✗ NOT READY — {issues} issue(s) to resolve")
        print()
        print("  To resolve:")
        step = 1
        if not sdk_ok:
            if py_status == "load_error":
                print(f"    {step}. Reinstall Python SDK: pip install --force-reinstall protegrity-ai-developer-python")
            elif py_status == "old":
                print(f"    {step}. Upgrade Python SDK: pip install --upgrade protegrity-ai-developer-python")
            elif java_ok is False:
                print(f"    {step}. Upgrade Java SDK to >= 1.1.0 in your pom.xml.")
            else:
                print(f"    {step}. Install at least one SDK (Python >= 1.2.1 or Java >= 1.1.0).")
            step += 1
        if not ok or not host:
            print(f"    {step}. Set Team Edition host: export PTY_CP_HOST=<your-cloud-protect-url>")
            step += 1
        if not auth_ok:
            for line in _auth_fix_hints(mode, detail, indent=f"    {step}. ",
                                        continuation="       "):
                print(line)
            step += 1
        if auth_works is False:
            print(f"    {step}. Authentication is configured but Cloud Protect rejected the request.")
            print("       - For aws_iam: confirm the IAM principal (profile, role, or keys) is")
            print(f"         allowed by the API Gateway resource policy / Lambda authorizer for {host}.")
            print("       - For bearer_token / oauth2: confirm the token is valid and not expired.")
            print("       - For mtls: confirm PTY_CLIENT_CERT / PTY_CLIENT_KEY are trusted by CP.")
            print("       - Confirm the Policy Agent Lambda has synced the policy to Cloud Protect")
            print("         (a freshly-deployed policy may take up to an hour without manual trigger).")
            step += 1
        if ppc_failed:
            print(f"    {step}. Create/deploy the Developer Edition policy on PPC:")
            print("       pty-migrate create-policy --ppc-host <your-ppc-host> --ppc-password <password> --full")
            step += 1
            ds_id_token = dev_edition_uid if dev_edition_uid else "{id}"
            print(f"    {step}. Add the KMS export key to the DevEdition datastore:")
            print(f"       POST /pty/v2/pim/datastores/{ds_id_token}/export/keys with the KMS public-key PEM.")
            if dev_edition_uid:
                print("       Example:")
                print(f"         curl -k -X POST https://{ppc['host']}/pty/v2/pim/datastores/{dev_edition_uid}/export/keys \\")
                print("           -H \"Authorization: Bearer $TOKEN\" -H \"Content-Type: application/json\" \\")
                print("           -d '{\"algorithm\":\"RSA-OAEP-256\",\"pem\":\"<KMS-PUBLIC-KEY-PEM>\"}'")
            print("       (The cloud-side Policy Agent Lambda reads this key from its own")
            print("        PTY_DATASTORE_KEY env var — it is NOT a client-side variable.)")
            step += 1
            print(f"    {step}. Trigger the Policy Agent Lambda to sync the policy to Cloud Protect")
            print("       (runs hourly if CRON enabled, or invoke manually from AWS Lambda console).")
            step += 1
        if de_failed:
            print(f"    {step}. Re-run protect/unprotect test once the Policy Agent has synced.")
            step += 1
    print()

    return 0 if issues == 0 else 1
