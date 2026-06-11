"""
Pluggable authentication providers for the Protegrity SDK.

Each provider implements authenticate_request() to sign/authenticate outgoing
HTTP requests according to a specific auth mechanism.
"""

import os
import requests as http_requests

from appython.utils.exceptions import InitializationError


class AuthProvider:
    """Base class for authentication providers."""

    def authenticate_request(self, method, url, headers, body):
        """Sign/authenticate an outgoing request.

        Args:
            method: HTTP method (e.g., "POST").
            url: Full request URL.
            headers: Existing headers dict (will be mutated).
            body: Request body (dict).

        Returns:
            dict: Updated headers with auth credentials added.
        """
        raise NotImplementedError

    def initialize(self):
        """Perform any upfront auth (login, token fetch, etc.)."""
        pass

    def get_request_kwargs(self):
        """Return extra kwargs to pass to requests.post() (e.g., cert for mTLS).

        Returns:
            dict: Extra keyword arguments for requests.
        """
        return {}


class CognitoAuthProvider(AuthProvider):
    """Authenticates via Cognito login (Developer Edition behavior).

    Performs a login call to get a JWT token, then attaches
    the JWT and API key to every request.
    """

    def __init__(self, config):
        self._email = config.get("de_email")
        self._password = config.get("de_password")
        self._api_key = config.get("de_api_key")
        self._protect_host = config.get("protect_host")
        self._jwt_token = None

    def initialize(self):
        if not self._email or not self._password:
            raise InitializationError(
                err_msg="Authentication failed: Both DEV_EDITION_EMAIL and DEV_EDITION_PASSWORD must be provided."
            )
        if not self._api_key:
            raise InitializationError(
                err_msg="Authentication failed: DEV_EDITION_API_KEY must be provided."
            )

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self._api_key,
        }
        login_url = f"{self._protect_host}/auth/login"
        payload = {"email": self._email, "password": self._password}
        # Cap the login call so a stalled DE auth endpoint does not hang init.
        response = http_requests.post(login_url, json=payload, headers=headers, timeout=30)
        if response.status_code != 200:
            raise InitializationError(
                err_msg=f"{response.json().get('error', 'Could not authenticate user.')}"
            )
        self._jwt_token = response.json().get("jwt_token", None)

    def authenticate_request(self, method, url, headers, body):
        headers["x-api-key"] = self._api_key
        headers["Authorization"] = self._jwt_token
        return headers


class AWSIAMAuthProvider(AuthProvider):
    """Authenticates requests using AWS SigV4 signing.

    Requires botocore to be installed: pip install appython[aws]
    """

    def __init__(self, config):
        self._protect_host = config.get("protect_host")
        self._session = None
        self._credentials = None
        self._signer = None

    def initialize(self):
        try:
            import botocore.session
            import botocore.auth
            import botocore.awsrequest
        except ImportError:
            raise InitializationError(
                err_msg="aws_iam auth mode requires botocore. Install with: pip install appython[aws]"
            )

        session = botocore.session.get_session()
        self._credentials = session.get_credentials()
        if not self._credentials:
            raise InitializationError(
                err_msg="AWS credentials not found. Configure via AWS_PROFILE, "
                "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or instance role."
            )
        self._credentials = self._credentials.get_frozen_credentials()

    def authenticate_request(self, method, url, headers, body):
        import botocore.auth
        import botocore.awsrequest
        import json

        # Build an AWSRequest for signing
        body_bytes = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body
        aws_request = botocore.awsrequest.AWSRequest(
            method=method, url=url, headers=headers, data=body_bytes
        )

        # Sign with SigV4 for execute-api service
        signer = botocore.auth.SigV4Auth(self._credentials, "execute-api", self._region)
        signer.add_auth(aws_request)

        # Copy signed headers back
        headers.update(dict(aws_request.headers))
        return headers

    @property
    def _region(self):
        """Extract region from the protect host URL or fall back to env/default."""
        # Try to extract from URL like https://xxx.execute-api.us-east-1.amazonaws.com/...
        host = self._protect_host or ""
        parts = host.split(".")
        for i, part in enumerate(parts):
            if part == "execute-api" and i + 1 < len(parts):
                return parts[i + 1]
        # AWS_REGION is set by Lambda and honored by boto3/awscli;
        # AWS_DEFAULT_REGION is the older variant. Accept either.
        return os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION") or "us-east-1"


class BearerTokenAuthProvider(AuthProvider):
    """Authenticates with a Bearer token (static or fetched via OAuth2 client_credentials)."""

    def __init__(self, config):
        self._static_token = config.get("static_token")
        self._token_endpoint = config.get("token_endpoint")
        self._client_id = config.get("client_id")
        self._client_secret = config.get("client_secret")
        self._access_token = None

    def initialize(self):
        if self._static_token:
            self._access_token = self._static_token
            return

        if not self._token_endpoint:
            raise InitializationError(
                err_msg="bearer_token mode requires PTY_STATIC_TOKEN or "
                "PTY_TOKEN_ENDPOINT + PTY_CLIENT_ID + PTY_CLIENT_SECRET."
            )
        self._fetch_token()

    def _fetch_token(self):
        """Fetch access token from OAuth2 token endpoint using client_credentials grant."""
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        response = http_requests.post(
            self._token_endpoint,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if response.status_code != 200:
            raise InitializationError(
                err_msg=f"Failed to fetch OAuth2 token: {response.status_code} {response.text}"
            )
        self._access_token = response.json().get("access_token")

    def authenticate_request(self, method, url, headers, body):
        headers["Authorization"] = f"Bearer {self._access_token}"
        return headers


class NoneAuthProvider(AuthProvider):
    """No authentication — for internal/trusted networks."""

    def __init__(self, config):
        pass

    def authenticate_request(self, method, url, headers, body):
        return headers


class MTLSAuthProvider(AuthProvider):
    """Mutual TLS authentication via client certificates.

    Auth is at the TLS layer, not HTTP headers.
    """

    def __init__(self, config):
        self._client_cert = config.get("client_cert")
        self._client_key = config.get("client_key")
        self._ca_cert = config.get("ca_cert")

    def initialize(self):
        if not self._client_cert or not self._client_key:
            raise InitializationError(
                err_msg="mtls mode requires PTY_CLIENT_CERT and PTY_CLIENT_KEY."
            )

    def authenticate_request(self, method, url, headers, body):
        # mTLS auth is at TLS handshake layer — no header changes needed
        return headers

    def get_request_kwargs(self):
        kwargs = {"cert": (self._client_cert, self._client_key)}
        if self._ca_cert:
            kwargs["verify"] = self._ca_cert
        return kwargs


# Registry of auth mode string → provider class
_PROVIDER_REGISTRY = {
    "cognito": CognitoAuthProvider,
    "aws_iam": AWSIAMAuthProvider,
    "bearer_token": BearerTokenAuthProvider,
    "none": NoneAuthProvider,
    "mtls": MTLSAuthProvider,
}


def create_auth_provider(config):
    """Factory: create and initialize the appropriate auth provider from config.

    Args:
        config: Configuration dict from load_config().

    Returns:
        AuthProvider: An initialized auth provider instance.

    Raises:
        InitializationError: If auth mode is missing or invalid.
    """
    auth_mode = config.get("auth_mode")
    if not auth_mode:
        raise InitializationError(
            err_msg="Cannot determine auth mode. Set PTY_AUTH_MODE or provide DEV_EDITION_* variables."
        )

    provider_class = _PROVIDER_REGISTRY.get(auth_mode)
    if not provider_class:
        valid_modes = ", ".join(_PROVIDER_REGISTRY.keys())
        raise InitializationError(
            err_msg=f"Invalid PTY_AUTH_MODE='{auth_mode}'. Valid modes: {valid_modes}"
        )

    provider = provider_class(config)
    provider.initialize()
    return provider
