"""Loader for bundled DE policy payload files."""

import json
from pathlib import Path

_PAYLOAD_DIR = Path(__file__).parent


def load_payload(name):
    """Load a payload JSON file by resource name.

    Args:
        name: Resource name (e.g., 'dataelements', 'roles', 'rules').

    Returns:
        Parsed JSON (list or dict).
    """
    # Map resource names to filenames
    filename_map = {
        "datastores": "datastores.json",
        "sources": "sources.json",
        "roles": "roles.json",
        "alphabets": "alphabets.json",
        "masks": "masks.json",
        "dataelements": "dataelements.json",
        "applications": "trusted_apps.json",
        "policies": "policies.json",
        "rules": "rules.json",
        "deploy": "deploy_policy_ta.json",
        "members": "members.json",
    }
    filename = filename_map.get(name)
    if not filename:
        raise ValueError(f"Unknown payload resource: {name}")

    path = _PAYLOAD_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_all_payloads():
    """Load all payload files into a dict keyed by resource name.

    Returns:
        dict: {resource_name: payload_data}
    """
    resources = [
        "datastores", "sources", "roles", "alphabets", "masks",
        "dataelements", "applications", "policies", "rules", "deploy", "members",
    ]
    return {name: load_payload(name) for name in resources}
