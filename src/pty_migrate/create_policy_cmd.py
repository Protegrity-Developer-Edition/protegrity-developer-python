"""pty-migrate create-policy — create DE policy on PPC (Team Edition).

Reads bundled DE policy payloads and creates resources on PPC.
By default, filters to only data elements and roles reported by usage stats.
If no stats exist or --full is specified, creates the complete DE policy.

Idempotent: queries PPC for existing resources and only creates the delta.
"""

import json
import os
import sys
import getpass
from pathlib import Path

from pty_migrate.payloads import load_all_payloads
from pty_migrate.ppc_client import PPCClient


# Resource creation order — dependencies first
RESOURCE_ORDER = [
    "init",
    "datastores",
    "sources",
    "roles",
    "members",
    "alphabets",
    "masks",
    "dataelements",
    "applications",
    "policies",
    "rules",
    "deploy",
]


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


def _get_existing_names(client):
    """Query PPC for existing resource names (for delta computation)."""
    return {
        "datastores": {item.get("name", "").lower() for item in client.list_datastores()},
        "sources": {item.get("name", "").lower() for item in client.list_sources()},
        "roles": {item.get("name", "").lower() for item in client.list_roles()},
        "alphabets": {item.get("label", item.get("name", "")).lower() for item in client.list_alphabets()},
        "masks": {item.get("name", "").lower() for item in client.list_masks()},
        "dataelements": {item.get("name", "").lower() for item in client.list_data_elements()},
        "applications": {item.get("name", "").lower() for item in client.list_applications()},
        "policies": {item.get("name", "").lower() for item in client.list_policies()},
    }


def _build_uid_maps(client, payloads):
    """Build mappings from payload positional index → actual PPC UID.

    The payload files use sequential numeric strings ("1", "2", ...) as UIDs,
    corresponding to the position of each resource in the payload array. On a
    real PPC that already has resources, the actual assigned UIDs differ.

    This queries the PPC for current resource UIDs by name and builds a mapping.

    Returns:
        dict with keys: roles, dataelements, sources, datastores, policies, applications
        Each value is a dict mapping payload_index_str → actual_uid_str.
    """
    def _name_to_uid(items, name_key="name"):
        """Build {lowercase_name: uid_str} from a PPC list response."""
        result = {}
        for item in items:
            name = item.get(name_key, "").lower()
            uid = str(item.get("uid", ""))
            if name and uid:
                result[name] = uid
        return result

    ppc_roles = _name_to_uid(client.list_roles())
    ppc_des = _name_to_uid(client.list_data_elements())
    ppc_sources = _name_to_uid(client.list_sources())
    ppc_datastores = _name_to_uid(client.list_datastores())
    ppc_policies = _name_to_uid(client.list_policies())
    ppc_apps = _name_to_uid(client.list_applications())
    ppc_masks = _name_to_uid(client.list_masks())

    # Map payload position (1-based) to actual UID by looking up the name
    def _build_map(payload_list, ppc_lookup, name_key="name"):
        mapping = {}
        for i, item in enumerate(payload_list, 1):
            name = item.get(name_key, "").lower()
            actual_uid = ppc_lookup.get(name)
            if actual_uid:
                mapping[str(i)] = actual_uid
        return mapping

    return {
        "roles": _build_map(payloads["roles"], ppc_roles),
        "dataelements": _build_map(payloads["dataelements"], ppc_des),
        "sources": _build_map(payloads["sources"], ppc_sources),
        "datastores": _build_map(payloads["datastores"], ppc_datastores),
        "policies": _build_map(payloads["policies"], ppc_policies),
        "applications": _build_map(payloads["applications"], ppc_apps),
        "masks": _build_map(payloads["masks"], ppc_masks),
    }


def _filter_payloads_by_stats(payloads, stats):
    """Filter payloads to only include resources reported in usage stats.

    Filters data elements and roles. Infrastructure resources (datastores,
    sources, alphabets, masks, applications, policies) are always included
    as they are prerequisites.

    Args:
        payloads: Full DE policy payloads dict.
        stats: Usage stats dict with 'data_elements' and 'policy_users' keys.

    Returns:
        Filtered payloads dict.
    """
    stats_de_names = {name.lower() for name in stats.get("data_elements", {}).keys()}
    stats_user_names = {name.lower() for name in stats.get("policy_users", {}).keys()}

    filtered = dict(payloads)  # Shallow copy

    # Filter data elements to those in stats
    if stats_de_names:
        filtered["dataelements"] = [
            de for de in payloads["dataelements"]
            if de["name"].lower() in stats_de_names
        ]

    # Build role index (1-based position in the full roles list)
    all_roles = payloads["roles"]
    role_name_to_index = {}
    for i, role in enumerate(all_roles, 1):
        role_name_to_index[role["name"].lower()] = str(i)

    # Determine which roles contain the stats policy_users as members
    # Members is a dict of "roles/{uid}/members" -> [member_payloads]
    roles_containing_users = set()  # role indices (str)
    for endpoint, members in payloads["members"].items():
        parts = endpoint.split("/")
        if len(parts) >= 2:
            role_uid = parts[1]
            member_names = {m["name"].lower() for m in members}
            if member_names & stats_user_names:
                roles_containing_users.add(role_uid)

    # Filter roles to those containing stats policy_users
    if stats_user_names:
        filtered["roles"] = [
            role for role in all_roles
            if role_name_to_index.get(role["name"].lower()) in roles_containing_users
        ]

    # Filter members to only matching roles, only used members
    filtered_members = {}
    for endpoint, members in payloads["members"].items():
        parts = endpoint.split("/")
        if len(parts) >= 2:
            role_uid = parts[1]
            if role_uid in roles_containing_users:
                # Only include members that are in stats policy_users
                used_members = [
                    m for m in members
                    if m["name"].lower() in stats_user_names
                ]
                if used_members:
                    filtered_members[endpoint] = used_members
    filtered["members"] = filtered_members

    # Filter rules to only matching role × data element combinations
    filtered_role_uids = roles_containing_users

    all_des = payloads["dataelements"]
    de_name_to_index = {}
    for i, de in enumerate(all_des, 1):
        de_name_to_index[de["name"].lower()] = str(i)

    filtered_de_uids = set()
    for de_name in stats_de_names:
        uid = de_name_to_index.get(de_name)
        if uid:
            filtered_de_uids.add(uid)

    filtered["rules"] = [
        rule for rule in payloads["rules"]
        if str(rule.get("role")) in filtered_role_uids
        and str(rule.get("dataElement")) in filtered_de_uids
    ]

    return filtered


def _compute_delta(payloads, existing):
    """Remove resources that already exist on PPC.

    Args:
        payloads: Filtered payloads to create.
        existing: Dict of existing resource names on PPC (lowercase sets).

    Returns:
        Payloads with already-existing items removed.
    """
    delta = dict(payloads)

    delta["datastores"] = [
        p for p in payloads.get("datastores", [])
        if p.get("name", "").lower() not in existing.get("datastores", set())
    ]
    delta["sources"] = [
        p for p in payloads.get("sources", [])
        if p.get("name", "").lower() not in existing.get("sources", set())
    ]
    delta["roles"] = [
        p for p in payloads.get("roles", [])
        if p.get("name", "").lower() not in existing.get("roles", set())
    ]
    delta["alphabets"] = [
        p for p in payloads.get("alphabets", [])
        if p.get("label", p.get("name", "")).lower() not in existing.get("alphabets", set())
    ]
    delta["masks"] = [
        p for p in payloads.get("masks", [])
        if p.get("name", "").lower() not in existing.get("masks", set())
    ]
    delta["dataelements"] = [
        p for p in payloads.get("dataelements", [])
        if p.get("name", "").lower() not in existing.get("dataelements", set())
    ]
    delta["applications"] = [
        p for p in payloads.get("applications", [])
        if p.get("name", "").lower() not in existing.get("applications", set())
    ]
    delta["policies"] = [
        p for p in payloads.get("policies", [])
        if p.get("name", "").lower() not in existing.get("policies", set())
    ]
    # Rules and members are always attempted (PPC handles duplicates via 409)
    delta["rules"] = payloads.get("rules", [])
    delta["members"] = payloads.get("members", {})
    delta["deploy"] = payloads.get("deploy", [])

    return delta


def _print_plan(delta, dry_run=False):
    """Print what will be created."""
    prefix = "[DRY RUN] " if dry_run else ""
    print(f"\n{prefix}Resources to create:")
    print(f"  Datastores:     {len(delta.get('datastores', []))}")
    print(f"  Sources:        {len(delta.get('sources', []))}")
    print(f"  Roles:          {len(delta.get('roles', []))}")
    members_count = sum(len(v) for v in delta.get("members", {}).values())
    print(f"  Members:        {members_count}")
    print(f"  Alphabets:      {len(delta.get('alphabets', []))}")
    print(f"  Masks:          {len(delta.get('masks', []))}")
    print(f"  Data elements:  {len(delta.get('dataelements', []))}")
    print(f"  Applications:   {len(delta.get('applications', []))}")
    print(f"  Policies:       {len(delta.get('policies', []))}")
    print(f"  Rules:          {len(delta.get('rules', []))}")
    print()

    if delta.get("dataelements"):
        de_names = [de["name"] for de in delta["dataelements"]]
        print(f"  Data elements: {', '.join(de_names)}")
    if delta.get("roles"):
        role_names = [r["name"] for r in delta["roles"]]
        print(f"  Roles: {', '.join(role_names)}")
    print()


def run_create_policy(args):
    """Execute the create-policy command."""
    # Resolve PPC connection from CLI args + env vars + config file.
    # Password precedence: env var > --ppc-password flag > interactive prompt.
    # Env is preferred so secrets don't end up in shell history or `ps`.
    from pty_migrate.config import resolve
    args.ppc_host = resolve(args.ppc_host, "PTY_PPC_HOST", "ppc_host")
    args.ppc_user = resolve(args.ppc_user, "PTY_PPC_USER", "ppc_user", "admin")
    args.ppc_port = resolve(getattr(args, "ppc_port", None), "PTY_PPC_PORT", "ppc_port", 443)
    try:
        args.ppc_port = int(args.ppc_port)
    except (TypeError, ValueError):
        args.ppc_port = 443

    # Password precedence: --ppc-password flag > PTY_PPC_PASSWORD env
    #   > ppc_password in ~/.protegrity/config.yaml (opt-in + chmod 600)
    #   > interactive prompt.
    from pty_migrate.config import resolve_password
    cli_password = args.ppc_password
    resolved_pw, pw_source = resolve_password(
        cli_password, "PTY_PPC_PASSWORD", "ppc_password"
    )
    if pw_source == "cli":
        print("  ⚠ --ppc-password on the command line is recorded in shell history.")
        print("    Prefer: export PTY_PPC_PASSWORD='...'  (or omit to be prompted).")
        args.ppc_password = resolved_pw
    elif pw_source == "env":
        args.ppc_password = resolved_pw
        if cli_password and cli_password != resolved_pw:
            print("  · Ignoring --ppc-password (PTY_PPC_PASSWORD env var takes precedence).")
    elif pw_source == "file":
        args.ppc_password = resolved_pw
        print("  · PPC password loaded from ~/.protegrity/config.yaml (chmod 600 verified).")
    elif args.ppc_host and sys.stdin.isatty():
        try:
            args.ppc_password = getpass.getpass(
                f"PPC password for '{args.ppc_user}'@{args.ppc_host}: "
            )
        except (EOFError, KeyboardInterrupt):
            print("\n  ✗ Aborted.")
            return 1
    else:
        args.ppc_password = None

    # Workbench password: --flag > env > file (opt-in) > reuse admin password.
    wb_cli = getattr(args, "workbench_password", None)
    resolved_wb, wb_pw_source = resolve_password(
        wb_cli, "PTY_WORKBENCH_PASSWORD", "workbench_password"
    )
    if wb_pw_source == "cli":
        args.workbench_password = resolved_wb
        wb_source = "--workbench-password flag"
    elif wb_pw_source == "env":
        args.workbench_password = resolved_wb
        wb_source = "PTY_WORKBENCH_PASSWORD env var"
    elif wb_pw_source == "file":
        args.workbench_password = resolved_wb
        wb_source = "~/.protegrity/config.yaml"
    else:
        args.workbench_password = args.ppc_password
        wb_source = None  # reused from admin — message printed only if we hit the workbench branch

    args._workbench_password_explicit = wb_source is not None
    args._workbench_password_source = wb_source

    missing = [name for name, val in
               (("--ppc-host / PTY_PPC_HOST", args.ppc_host),
                ("password (PTY_PPC_PASSWORD env, --ppc-password, or prompt)",
                 args.ppc_password))
               if not val]
    if missing:
        print(f"  ✗ Missing PPC credentials: {', '.join(missing)}")
        print("    Set the environment variables or pass the matching CLI flags.")
        return 1

    # 1. Load bundled payloads (full DE policy definitions)
    payloads = load_all_payloads()

    # 2. Load stats (determines what to filter)
    stats, stats_path = _load_stats(getattr(args, "stats_file", None))
    full_mode = getattr(args, "full", False)

    # Keep full payloads for UID mapping (rules reference positions in full list)
    full_payloads = payloads

    if stats and not full_mode:
        print(f"Stats found at: {stats_path}")
        de_names = list(stats.get("data_elements", {}).keys())
        user_names = list(stats.get("policy_users", {}).keys())
        print(f"  Data elements in stats: {len(de_names)} — {', '.join(de_names)}")
        print(f"  Policy users in stats:  {len(user_names)} — {', '.join(user_names)}")
        print()
        payloads = _filter_payloads_by_stats(payloads, stats)
    elif full_mode:
        print("Full mode: creating complete DE policy (ignoring stats filter)")
        print()
    else:
        print(f"No stats found at: {stats_path}")
        print("Creating complete DE policy (all data elements and roles)")
        print()

    # 3. Dry-run: show plan and exit
    if getattr(args, "dry_run", False):
        _print_plan(payloads, dry_run=True)
        print("[DRY RUN] No changes made on PPC.")
        return 0

    # 4. Connect to PPC
    user_was_explicit = getattr(args, "_ppc_user_explicit", False)
    print(f"Connecting to PPC at {args.ppc_host}:{args.ppc_port}...")
    client = PPCClient(args.ppc_host, args.ppc_user, args.ppc_password, args.ppc_port)

    try:
        client.authenticate()
        print(f"  ✓ Authenticated as '{args.ppc_user}'")
    except Exception as e:
        if "401" in str(e) and not user_was_explicit:
            # Default user failed, try the alternate
            alt_user = "workbench" if args.ppc_user == "admin" else "admin"
            print(f"  · User '{args.ppc_user}' failed, trying '{alt_user}'...")
            client = PPCClient(args.ppc_host, alt_user, args.ppc_password, args.ppc_port)
            try:
                client.authenticate()
                print(f"  ✓ Authenticated as '{alt_user}'")
            except Exception as e2:
                print(f"  ✗ Authentication failed for both '{args.ppc_user}' and '{alt_user}': {e2}")
                return 1
        else:
            print(f"  ✗ Authentication failed: {e}")
            return 1

    # 4b. Ensure PIM-capable user
    # PIM APIs require 'workbench_management_policy_write' permission
    # (via 'workbench_administrator' role). If the current user lacks PIM
    # access, attempt to set up the 'workbench' user automatically.
    pim_test = client._get("/v2/pim/datastores")
    if pim_test.status_code == 403:
        if user_was_explicit:
            # User explicitly chose this user — don't second-guess
            print(f"\n  ✗ User '{client._user}' lacks PIM permissions (HTTP 403)")
            print("    The PIM API requires the 'workbench_administrator' role.")
            print("    Use --ppc-user with a PIM-capable user, or omit --ppc-user")
            print("    to let the script auto-create the 'workbench' user.")
            return 1

        print(f"\n  · User '{client._user}' lacks PIM permissions, setting up 'workbench' user...")
        wb_password = args.workbench_password
        if args._workbench_password_explicit:
            print(f"    Using workbench password from {args._workbench_password_source}.")
        else:
            print(f"    Using same password as '{args.ppc_user}' for workbench user")
            print("    (override with --workbench-password or PTY_WORKBENCH_PASSWORD).")
        wb_exists = client.user_exists("workbench")
        if not wb_exists:
            created, resp = client.create_user(
                "workbench", wb_password,
                roles=["workbench_administrator"]
            )
            if created:
                print("  ✓ Created 'workbench' user with workbench_administrator role")
            else:
                print(f"  ✗ Failed to create workbench user: {resp.status_code} {resp.text}")
                return 1
        else:
            print("  · 'workbench' user already exists")

        # Ensure workbench_administrator role has all required PIM permissions
        wb_permissions = [
            "workbench_management_policy_write",
            "workbench_management_policy_read",
            "workbench_deployment_immutablepackage_export",
            "workbench_deployment_certificate_export",
            "cli_access",
            "can_create_token",
        ]
        if client.ensure_role_permissions("workbench_administrator", wb_permissions):
            print("  ✓ Role 'workbench_administrator' permissions confirmed")
        else:
            print("  · Could not update role permissions (non-critical)")

        # Re-authenticate as workbench
        try:
            client.re_authenticate("workbench", wb_password)
            print("  ✓ Re-authenticated as 'workbench'")
        except Exception as e:
            if wb_exists:
                # workbench was pre-existing with a different password
                print("  ✗ Cannot authenticate as 'workbench' (password mismatch)")
                if args._workbench_password_explicit:
                    print("    The provided workbench password is wrong; pass the correct one.")
                else:
                    print(f"    The 'workbench' user pre-exists with a different password than '{args.ppc_user}'.")
                    print("    Re-run with --workbench-password '<workbench-password>' or")
                    print("    export PTY_WORKBENCH_PASSWORD='<workbench-password>'.")
            else:
                print(f"  ✗ Failed to authenticate as newly created 'workbench': {e}")
            return 1

    # 5. Initialize PIM if needed
    print("\nChecking PIM initialization...")
    try:
        client.init_pim()
        print("  ✓ PIM ready")
    except Exception as e:
        print(f"  ✗ PIM initialization failed: {e}")
        return 1

    # 6. Query existing resources (for delta computation)
    print("Querying existing resources on PPC...")
    existing = _get_existing_names(client)
    print(f"  Found: {len(existing['dataelements'])} DEs, {len(existing['roles'])} roles, "
          f"{len(existing['policies'])} policies")

    # 7. Compute delta
    delta = _compute_delta(payloads, existing)
    _print_plan(delta)

    total_new = (
        len(delta["datastores"]) + len(delta["sources"]) + len(delta["roles"])
        + len(delta["alphabets"]) + len(delta["masks"]) + len(delta["dataelements"])
        + len(delta["applications"]) + len(delta["policies"])
    )
    if total_new == 0 and not delta["rules"] and not delta["members"]:
        if not delta.get("deploy"):
            print("Nothing new to create. PPC already has all required resources.")
            return 0
        print("All resources exist. Verifying deployment...")
        print()

    # 8. Create resources in dependency order
    created = 0
    skipped = 0
    errors = 0

    # Datastores
    for payload in delta["datastores"]:
        ok, _ = client.create_datastore(payload)
        if ok:
            created += 1
            print(f"  ✓ Created datastore: {payload.get('name')}")
        else:
            skipped += 1

    # Sources
    for payload in delta["sources"]:
        ok, _ = client.create_source(payload)
        if ok:
            created += 1
            print(f"  ✓ Created source: {payload.get('name')}")
        else:
            skipped += 1

    # Roles
    for payload in delta["roles"]:
        ok, _ = client.create_role(payload)
        if ok:
            created += 1
            print(f"  ✓ Created role: {payload.get('name')}")
        else:
            skipped += 1

    # Alphabets
    for payload in delta["alphabets"]:
        ok, _ = client.create_alphabet(payload)
        if ok:
            created += 1
            print(f"  ✓ Created alphabet: {payload.get('label', payload.get('name'))}")
        else:
            skipped += 1

    # Masks
    for payload in delta["masks"]:
        ok, resp = client.create_mask(payload)
        if ok:
            created += 1
            print(f"  ✓ Created mask: {payload.get('name')}")
        else:
            skipped += 1

    # Build mask position→UID map so DEs that reference a mask via noEnc.maskUid
    # (stored as positional index in our payload) can be remapped to the actual
    # PPC-assigned UID before upload. Same shape as _build_uid_maps()["masks"]
    # but needed earlier in the flow (before DE upload).
    _ppc_masks_now = {
        item.get("name", "").lower(): str(item.get("uid", ""))
        for item in client.list_masks()
        if item.get("name") and item.get("uid")
    }
    _mask_pos_to_uid = {}
    for i, m in enumerate(full_payloads.get("masks", []), 1):
        actual = _ppc_masks_now.get(m.get("name", "").lower())
        if actual:
            _mask_pos_to_uid[str(i)] = actual

    # Same for alphabets — DEs reference them via unicodeGen2Token.alphabetUid
    # as positional indexes into local alphabets.json.
    _ppc_alphas_now = {
        (item.get("label") or item.get("name") or "").lower(): str(item.get("uid", ""))
        for item in client.list_alphabets()
        if item.get("uid")
    }
    _alpha_pos_to_uid = {}
    for i, a in enumerate(full_payloads.get("alphabets", []), 1):
        key = (a.get("label") or a.get("name") or "").lower()
        actual = _ppc_alphas_now.get(key)
        if actual:
            _alpha_pos_to_uid[str(i)] = actual

    # Data elements
    for payload in delta["dataelements"]:
        remapped = payload
        no_enc = payload.get("noEnc")
        u2 = payload.get("unicodeGen2Token")
        if isinstance(no_enc, dict) and "maskUid" in no_enc:
            remapped = dict(payload)
            remapped["noEnc"] = dict(no_enc)
            remapped["noEnc"]["maskUid"] = _mask_pos_to_uid.get(
                str(no_enc["maskUid"]), str(no_enc["maskUid"])
            )
        if isinstance(u2, dict) and "alphabetUid" in u2:
            if remapped is payload:
                remapped = dict(payload)
            new_u2 = dict(u2)
            new_u2["alphabetUid"] = _alpha_pos_to_uid.get(
                str(u2["alphabetUid"]), str(u2["alphabetUid"])
            )
            remapped["unicodeGen2Token"] = new_u2
        ok, resp = client.create_data_element(remapped)
        if ok:
            created += 1
            print(f"  ✓ Created data element: {payload.get('name')}")
        else:
            skipped += 1

    # Applications
    for payload in delta["applications"]:
        ok, _ = client.create_application(payload)
        if ok:
            created += 1
            print(f"  ✓ Created application: {payload.get('name')}")
        else:
            skipped += 1

    # Policies
    for payload in delta["policies"]:
        ok, _ = client.create_policy(payload)
        if ok:
            created += 1
            print(f"  ✓ Created policy: {payload.get('name')}")
        else:
            skipped += 1

    # 9. Build UID mappings — payload positional index → actual PPC UID
    # Must use full_payloads (not filtered) because rules reference positions
    # in the original full payload arrays (e.g., dataElement "8" = city at
    # position 8 in the full DE list).
    print("\nResolving resource UIDs...")
    uid_maps = _build_uid_maps(client, full_payloads)

    # Members — uses remapped role/source UIDs
    for endpoint, members in delta.get("members", {}).items():
        # Remap role UID in endpoint: "roles/{payload_uid}/members" → actual UID
        parts = endpoint.split("/")
        if len(parts) >= 2 and parts[0] == "roles":
            actual_role_uid = uid_maps["roles"].get(parts[1], parts[1])
            endpoint = f"roles/{actual_role_uid}/members"
        for member in members:
            # Remap source UID in member payload
            remapped_member = dict(member)
            if "source" in remapped_member:
                remapped_member["source"] = uid_maps["sources"].get(
                    remapped_member["source"], remapped_member["source"]
                )
            ok, _ = client.post_resource(endpoint, [remapped_member])
            if ok:
                created += 1
                print(f"  ✓ Added member: {member.get('name')} → {endpoint}")
            else:
                skipped += 1

    # Rules — remap role/dataElement UIDs to actual PPC UIDs
    policy_uid = uid_maps["policies"].get("1", "1")  # Our policy is position 1
    # DEs that use aes256CbcEnc don't support noAccessOperation=PROTECTED_VALUE.
    # Strip that field from rules targeting them. Positions are 1-based to
    # match the dataElement references in rules.json.
    cbc_de_positions = {
        str(i + 1)
        for i, de in enumerate(full_payloads.get("dataelements", []))
        if isinstance(de, dict) and "aes256CbcEnc" in de
    }
    rules_created = 0
    rules_skipped = 0
    rules_failed = 0
    first_error = None
    for rule in delta["rules"]:
        remapped_rule = dict(rule)
        if (
            str(rule.get("dataElement")) in cbc_de_positions
            and "noAccessOperation" in remapped_rule
        ):
            remapped_rule.pop("noAccessOperation", None)
        remapped_rule["role"] = uid_maps["roles"].get(
            str(rule.get("role")), str(rule.get("role"))
        )
        remapped_rule["dataElement"] = uid_maps["dataelements"].get(
            str(rule.get("dataElement")), str(rule.get("dataElement"))
        )
        if "mask" in remapped_rule:
            remapped_rule["mask"] = uid_maps["masks"].get(
                str(rule.get("mask")), str(rule.get("mask"))
            )
        ok, resp = client.create_rule(policy_uid, remapped_rule)
        if ok:
            rules_created += 1
        elif resp and resp.status_code == 400:
            rules_failed += 1
            if first_error is None:
                first_error = resp.text[:200]
        else:
            rules_skipped += 1
    if rules_created:
        print(f"  ✓ Created {rules_created} rules")
    if rules_skipped:
        print(f"  · {rules_skipped} rules already existed")
    if rules_failed:
        print(f"  ✗ {rules_failed} rules failed (400 Bad Request)")
        print(f"    First error: {first_error}")

    # Deploy — use actual datastore and policy UIDs
    ds_uid = uid_maps["datastores"].get("1", "1")  # Our datastore is position 1
    app_uid = uid_maps["applications"].get("1")  # None if app didn't resolve
    if delta.get("deploy"):
        # Only include the application in the deploy if we have a real PPC UID
        # for it. If app creation failed (e.g. description validation) and PPC
        # has no pre-existing app with the same name, skip it from the start to
        # avoid a spurious "Application 'N' does not exist" error.
        if app_uid:
            deploy_payload = {"policies": [policy_uid], "applications": [app_uid]}
        else:
            deploy_payload = {"policies": [policy_uid], "applications": []}
        ok, resp = client.deploy(ds_uid, deploy_payload)
        if ok:
            msg = f"  ✓ Policy deployed to datastore (ds={ds_uid}, policy={policy_uid})"
            print(msg)
            if not app_uid:
                print("    Note: application not included (creation failed or not found)")
        else:
            # Application might already be assigned to another datastore; retry without it
            deploy_payload_no_app = {"policies": [policy_uid], "applications": []}
            ok2, resp2 = client.deploy(ds_uid, deploy_payload_no_app)
            if ok2:
                print(f"  ✓ Policy deployed to datastore (ds={ds_uid}, policy={policy_uid})")
                print("    Note: application not included (already assigned elsewhere)")
            else:
                # Use the most relevant response for error reporting
                err_resp = resp2 if resp2 is not None else resp
                status = getattr(err_resp, 'status_code', '?') if err_resp else '?'
                body = ''
                if err_resp is not None:
                    try:
                        body = err_resp.text[:200]
                    except Exception:
                        pass
                print(f"  ✗ Deployment failed (HTTP {status}): {body}")
                errors += 1

    # Summary
    print(f"\n{'─' * 50}")
    print(f"Summary: {created} created, {skipped} skipped (already existed)")
    if errors:
        print(f"  {errors} errors")
        return 1
    print("Done.")

    # Next steps: export key guidance
    # Re-resolve the datastore UID from PPC so the printed curl reflects the
    # actual id (e.g. after a reset the same logical datastore can land at id=2).
    ds_uid_for_next_steps = ds_uid
    target_ds_name = ""
    if full_payloads.get("datastores"):
        target_ds_name = full_payloads["datastores"][0].get("name", "").lower()
    actual_datastores = client.list_datastores()
    matched = next(
        (d for d in actual_datastores
         if d.get("name", "").lower() == target_ds_name and d.get("uid")),
        None,
    )
    if matched:
        ds_uid_for_next_steps = str(matched["uid"])
    elif actual_datastores:
        first_uid = actual_datastores[0].get("uid")
        if first_uid:
            ds_uid_for_next_steps = str(first_uid)

    print(f"\n{'─' * 50}")
    print("Next steps — Policy Agent setup:")
    print("")
    print("  1. Add the KMS export key to the datastore so the Policy Agent can")
    print("     export the encrypted policy package:")
    print("")
    print("     curl -k -H \"Authorization: Bearer $TOKEN\" \\")
    print("       -H \"Content-Type: application/json\" \\")
    print(f"       -X POST https://{args.ppc_host}/pty/v2/pim/datastores/{ds_uid_for_next_steps}/export/keys \\")
    print("       -d '{\"algorithm\":\"RSA-OAEP-256\",\"pem\":\"<KMS-PUBLIC-KEY-PEM>\"}'")
    print("")
    print("     The fingerprint returned must match PTY_DATASTORE_KEY on the Policy Agent Lambda.")
    print("")
    print("  2. Trigger the Policy Agent Lambda (or wait for the hourly CRON schedule).")
    print("")
    print("  3. Run: pty-migrate check")
    print()
    return 0
