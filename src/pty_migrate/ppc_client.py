"""PPC Admin API client for pty-migrate create-policy.

Provides full PIM v2 API coverage for creating the DE policy on a
Team Edition PPC cluster. Supports JWT auth with auto-refresh.
"""

import logging
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class PPCClient:
    """Client for Protegrity PPC (PIM v2) Admin API with JWT auto-refresh."""

    def __init__(self, host, user, password, port=443):
        self._base_url = f"https://{host}:{port}/pty"
        self._user = user
        self._password = password
        self._access_token = None
        self._refresh_token = None
        self._token_expiry = 0
        self._refresh_expiry = 0
        self._session = requests.Session()
        self._session.verify = False
        self._session.timeout = 30

    # ──────────────────────────────────────────────────────────
    # Authentication with auto-refresh
    # ──────────────────────────────────────────────────────────

    def authenticate(self):
        """Obtain JWT tokens from PPC auth endpoint.

        PPC has two login endpoints:
        - /api/v1/auth/login/token: Returns token in 'pty_access_jwt_token' header.
          This token is recognized by the gateway's ext auth SecurityPolicy.
        - /pty/v1/auth/login/token: Returns token in JSON body. This token is NOT
          recognized by the gateway ext auth (causes 401 on protected routes).

        We try the header-based endpoint first, falling back to the body-based one.
        """
        # Try header-based auth first (gateway-compatible)
        base = self._base_url[:-4] if self._base_url.endswith("/pty") else self._base_url
        url = f"{base}/api/v1/auth/login/token"
        resp = self._session.post(
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"loginname": self._user, "password": self._password},
        )
        if resp.status_code == 200:
            token = resp.headers.get("pty_access_jwt_token", "").strip()
            if token:
                self._access_token = token
                self._refresh_token = None  # header-based auth doesn't return refresh token
                self._token_expiry = time.time() + 300
                self._session.headers["Authorization"] = f"Bearer {self._access_token}"
                logger.debug("PPC authentication successful (header-based)")
                return

        # Fallback to JSON body-based auth
        url = f"{self._base_url}/v1/auth/login/token"
        resp = self._session.post(
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"loginname": self._user, "password": self._password},
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Authentication failed: {resp.status_code} {resp.text}")
        data = resp.json().get("data", resp.json())
        self._access_token = data.get("accessToken") or data.get("token") or data.get("access_token")
        self._refresh_token = data.get("refreshToken")
        if not self._access_token:
            raise RuntimeError(f"No token in auth response: {list(data.keys())}")
        self._token_expiry = time.time() + data.get("expiresIn", 300)
        self._refresh_expiry = time.time() + data.get("refreshExpiresIn", 900)
        self._session.headers["Authorization"] = f"Bearer {self._access_token}"
        logger.debug("PPC authentication successful (body-based)")

    def _ensure_auth(self):
        """Refresh token if expired."""
        now = time.time()
        if self._access_token is None:
            self.authenticate()
        elif now >= (self._token_expiry - 30):
            if self._refresh_token and now < (self._refresh_expiry - 10):
                self._refresh()
            else:
                self.authenticate()

    def _refresh(self):
        """Refresh the access token."""
        url = f"{self._base_url}/v1/auth/login/token/refresh"
        resp = self._session.post(url, json={"refreshToken": self._refresh_token})
        if resp.status_code != 200:
            logger.debug("Token refresh failed, re-authenticating")
            self.authenticate()
            return
        data = resp.json().get("data", resp.json())
        self._access_token = data.get("accessToken") or data.get("token")
        self._refresh_token = data.get("refreshToken", self._refresh_token)
        self._token_expiry = time.time() + data.get("expiresIn", 300)
        self._session.headers["Authorization"] = f"Bearer {self._access_token}"

    # ──────────────────────────────────────────────────────────
    # Generic HTTP helpers
    # ──────────────────────────────────────────────────────────

    def _post(self, path, payload):
        """POST to PPC API with auto-refresh."""
        self._ensure_auth()
        url = f"{self._base_url}{path}"
        return self._session.post(url, json=payload)

    def _get(self, path):
        """GET from PPC API with auto-refresh."""
        self._ensure_auth()
        url = f"{self._base_url}{path}"
        return self._session.get(url)

    def post_resource(self, endpoint, payload):
        """POST a resource payload. Returns (created: bool, response).

        Handles 409 as 'already exists'. Returns (False, resp) on 400/other
        client errors without raising. Non-409 4xx failures are reported via
        `_warn_failed_create` so every caller gets visibility for free.

        Some PPC endpoints (notably role-member links) return 400 with a body
        like 'must be unique' / 'already exists' instead of 409 for duplicate
        creates. We treat those as the same idempotent skip as 409.
        """
        resp = self._post(f"/v2/pim/{endpoint}", payload)
        if resp.status_code in (200, 201, 204):
            return True, resp
        if resp.status_code == 409:
            return False, resp
        if resp.status_code >= 500:
            resp.raise_for_status()
        if resp.status_code == 400 and self._is_already_exists(resp):
            return False, resp
        self._warn_failed_create(endpoint, payload, resp)
        return False, resp

    @staticmethod
    def _is_already_exists(resp):
        """Return True if a 400 response really means 'already exists'."""
        try:
            body = resp.text.lower()
        except Exception:
            return False
        return (
            "already exists" in body
            or "must be unique" in body
            or "duplicate" in body
        )

    @staticmethod
    def _warn_failed_create(endpoint, payload, resp):
        """Surface non-409 4xx failures from `post_resource` to the CLI."""
        kind = endpoint.rstrip("/").split("/")[-1]
        name = ""
        if isinstance(payload, dict):
            name = (
                payload.get("name")
                or payload.get("label")
                or payload.get("username")
                or ""
            )
        elif isinstance(payload, list) and payload and isinstance(payload[0], dict):
            name = payload[0].get("name") or payload[0].get("username") or ""
        try:
            body = resp.text[:500]
        except Exception:
            body = ""
        print(f"  \u2717 Failed to create {kind} '{name}': HTTP {resp.status_code} {body}")

    # ──────────────────────────────────────────────────────────
    # PIM initialization
    # ──────────────────────────────────────────────────────────

    def is_pim_initialized(self):
        """Check if PIM is initialized by querying datastores."""
        try:
            resp = self._get("/v2/pim/datastores")
            return resp.status_code == 200
        except Exception:
            return False

    def init_pim(self):
        """Initialize PIM (first-time setup). Idempotent."""
        if self.is_pim_initialized():
            logger.debug("PIM already initialized")
            return True
        resp = self._post("/v2/pim/init", {})
        if resp.status_code in (200, 201, 204, 409):
            return True
        resp.raise_for_status()
        return True

    # ──────────────────────────────────────────────────────────
    # List resources (for delta computation)
    # ──────────────────────────────────────────────────────────

    def _parse_list_response(self, resp):
        """Parse a list API response into a list of items."""
        if resp.status_code != 200:
            return []
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("data", data.get("items", []))
        return []

    def list_datastores(self):
        """Get existing datastores."""
        return self._parse_list_response(self._get("/v2/pim/datastores"))

    def list_sources(self):
        """Get existing sources."""
        return self._parse_list_response(self._get("/v2/pim/sources"))

    def list_roles(self):
        """Get existing roles."""
        return self._parse_list_response(self._get("/v2/pim/roles"))

    def list_alphabets(self):
        """Get existing alphabets."""
        return self._parse_list_response(self._get("/v2/pim/alphabets"))

    def list_masks(self):
        """Get existing masks."""
        return self._parse_list_response(self._get("/v2/pim/masks"))

    def list_data_elements(self):
        """Get existing data elements."""
        return self._parse_list_response(self._get("/v2/pim/dataelements"))

    def list_applications(self):
        """Get existing trusted applications."""
        return self._parse_list_response(self._get("/v2/pim/applications"))

    def list_policies(self):
        """Get existing policies."""
        return self._parse_list_response(self._get("/v2/pim/policies"))

    def list_rules(self, policy_id="1"):
        """Get existing rules for a policy."""
        return self._parse_list_response(self._get(f"/v2/pim/policies/{policy_id}/rules"))

    def list_role_members(self, role_id):
        """Get members of a role."""
        return self._parse_list_response(self._get(f"/v2/pim/roles/{role_id}/members"))

    def list_export_keys(self, datastore_id):
        """Get export keys registered for a datastore."""
        return self._parse_list_response(
            self._get(f"/v2/pim/datastores/{datastore_id}/export/keys")
        )

    # ──────────────────────────────────────────────────────────
    # Create resources
    # ──────────────────────────────────────────────────────────

    def create_datastore(self, payload):
        """Create a datastore."""
        return self.post_resource("datastores", payload)

    def create_source(self, payload):
        """Create a source."""
        return self.post_resource("sources", payload)

    def create_role(self, payload):
        """Create a role from full payload."""
        return self.post_resource("roles", payload)

    def create_alphabet(self, payload):
        """Create an alphabet."""
        return self.post_resource("alphabets", payload)

    def create_mask(self, payload):
        """Create a mask."""
        return self.post_resource("masks", payload)

    def create_data_element(self, payload):
        """Create a data element from full payload."""
        return self.post_resource("dataelements", payload)

    def create_application(self, payload):
        """Create a trusted application."""
        return self.post_resource("applications", payload)

    def create_policy(self, payload):
        """Create a policy."""
        return self.post_resource("policies", payload)

    def create_rule(self, policy_id, payload):
        """Create a rule for a policy."""
        return self.post_resource(f"policies/{policy_id}/rules", payload)

    def add_members(self, role_uid, members_payload):
        """Add members to a role. members_payload is a list."""
        return self.post_resource(f"roles/{role_uid}/members", members_payload)

    def deploy(self, datastore_id="1", payload=None):
        """Deploy policy to a datastore."""
        if payload is None:
            payload = {"policies": ["1"], "applications": ["1"]}
        return self.post_resource(f"datastores/{datastore_id}/deploy", payload)

    # ──────────────────────────────────────────────────────────
    # User management (auth v1 API)
    # ──────────────────────────────────────────────────────────

    def list_users(self):
        """List all users via auth API."""
        resp = self._get("/v1/auth/users")
        if resp.status_code != 200:
            return []
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("data", data.get("items", []))
        return []

    def user_exists(self, username):
        """Check if a user exists."""
        users = self.list_users()
        return any(u.get("username") == username for u in users)

    def create_user(self, username, password, roles=None):
        """Create a user via auth API. Returns (created: bool, response)."""
        if roles is None:
            roles = []
        payload = {
            "username": username,
            "password": password,
            "roles": roles,
        }
        self._ensure_auth()
        url = f"{self._base_url}/v1/auth/users"
        resp = self._session.post(url, json=payload)
        if resp.status_code in (200, 201):
            return True, resp
        if resp.status_code == 409:
            return False, resp
        if resp.status_code == 400 and "exist" in resp.text.lower():
            return False, resp
        return False, resp

    def ensure_role_permissions(self, role_name, permissions):
        """Update a role with required permissions via PUT /v1/auth/roles."""
        self._ensure_auth()
        payload = {"name": role_name, "permissions": permissions}
        url = f"{self._base_url}/v1/auth/roles"
        resp = self._session.put(url, json=payload)
        return resp.status_code in (200, 201)

    def re_authenticate(self, user, password):
        """Switch identity by authenticating as a different user."""
        self._user = user
        self._password = password
        self._access_token = None
        self._refresh_token = None
        self.authenticate()
