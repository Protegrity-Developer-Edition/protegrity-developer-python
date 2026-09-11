"""
This module provides the RequestHandler class, which is responsible for sending HTTP requests to a specified API
endpoint using the `requests` library. It includes methods to send POST requests with JSON payloads and handle
the necessary headers for authentication.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


_DEFAULT_TIMEOUT = 30
_DEFAULT_MAX_RETRIES = 3

# One Session per (max_retries, backoff) combination so a connection pool can be
# reused across calls without re-mounting adapters on every request.
_session_cache: dict = {}


def _get_session(max_retries: int) -> requests.Session:
    sess = _session_cache.get(max_retries)
    if sess is not None:
        return sess
    sess = requests.Session()
    if max_retries > 0:
        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            status=max_retries,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE"]),
            backoff_factor=0.5,  # 0.5s, 1s, 2s, 4s, ...
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        sess.mount("https://", adapter)
        sess.mount("http://", adapter)  # NOSONAR - adapter prefix for local dev/testing, not an outbound URL
    _session_cache[max_retries] = sess
    return sess


def _resolve_resilience(config):
    """Pull timeout (seconds) and max_retries from an SDK config dict."""
    if not config:
        return _DEFAULT_TIMEOUT, _DEFAULT_MAX_RETRIES
    try:
        timeout = int(config.get("request_timeout", _DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = _DEFAULT_TIMEOUT
    try:
        retries = int(config.get("max_retries", _DEFAULT_MAX_RETRIES))
    except (TypeError, ValueError):
        retries = _DEFAULT_MAX_RETRIES
    return max(1, timeout), max(0, retries)


class RequestHandler:
    @staticmethod
    def send_api_request(
        payload: dict, base_url: str, api_key: str, jwt_token: str
    ) -> requests.Response:
        """
        Sends a POST request to the specified API endpoint with a JSON payload.
        Legacy method retained for backward compatibility.

        Parameters:
            payload (dict): The JSON-serializable payload to send in the request body.
            base_url (str): The full URL of the API endpoint to which the request is sent.
            api_key (str): API key for x-api-key header.
            jwt_token (str): JWT token for Authorization header.

        Returns:
            Response: The HTTP response object returned by the `requests.post` call.
        """
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "Authorization": jwt_token,
        }
        # Legacy path: apply default timeout but no retries (preserves caller
        # behavior for the older DE auth flow).
        response = requests.post(
            base_url, json=payload, headers=headers, timeout=_DEFAULT_TIMEOUT
        )
        return response

    @staticmethod
    def send_request(
        payload: dict, url: str, auth_provider, config: dict = None
    ) -> requests.Response:
        """
        Sends a POST request using the pluggable auth provider for authentication.

        Parameters:
            payload (dict): The JSON-serializable payload to send in the request body.
            url (str): The full URL of the API endpoint.
            auth_provider: An AuthProvider instance that signs the request.
            config (dict, optional): SDK config dict. Honors keys:
                - "request_timeout" (seconds, default 30) — per-attempt HTTP timeout.
                - "max_retries" (int, default 3) — retries on connection errors and
                  HTTP 429/5xx with exponential backoff and jitter. 0 disables retries.

        Returns:
            Response: The HTTP response object returned by the `requests.post` call.
        """
        timeout, max_retries = _resolve_resilience(config)
        headers = {"Content-Type": "application/json"}
        headers = auth_provider.authenticate_request("POST", url, headers, payload)
        kwargs = auth_provider.get_request_kwargs()
        session = _get_session(max_retries)
        response = session.post(
            url, json=payload, headers=headers, timeout=timeout, **kwargs
        )
        return response

