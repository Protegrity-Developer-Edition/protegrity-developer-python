"""Unit tests for the HTTP resilience layer (timeout + retry).

Covers `appython.service.request_handler` helpers introduced for
PTY_REQUEST_TIMEOUT / PTY_MAX_RETRIES. Behavior of urllib3's Retry itself
is upstream-tested, so here we assert the wiring: defaults, value parsing,
clamping, session caching, and that `send_request` forwards the resolved
timeout to the underlying transport.
"""

from unittest.mock import MagicMock, patch

import pytest
from urllib3.util.retry import Retry

from appython.service import request_handler
from appython.service.request_handler import (
    RequestHandler,
    _DEFAULT_MAX_RETRIES,
    _DEFAULT_TIMEOUT,
    _get_session,
    _resolve_resilience,
)

pytestmark = pytest.mark.migration


@pytest.fixture(autouse=True)
def _clear_session_cache():
    """Avoid cross-test pollution of the module-level session cache."""
    request_handler._session_cache.clear()
    yield
    request_handler._session_cache.clear()


# ── _resolve_resilience ────────────────────────────────────────────────────


class TestResolveResilience:

    def test_defaults_when_config_is_none(self):
        assert _resolve_resilience(None) == (_DEFAULT_TIMEOUT, _DEFAULT_MAX_RETRIES)

    def test_defaults_when_config_is_empty(self):
        assert _resolve_resilience({}) == (_DEFAULT_TIMEOUT, _DEFAULT_MAX_RETRIES)

    def test_explicit_int_values(self):
        assert _resolve_resilience({"request_timeout": 10, "max_retries": 5}) == (10, 5)

    def test_string_values_are_parsed(self):
        # Env vars surface as strings via SDKConfig.
        assert _resolve_resilience({"request_timeout": "10", "max_retries": "5"}) == (10, 5)

    def test_bad_timeout_falls_back_to_default(self):
        timeout, _ = _resolve_resilience({"request_timeout": "abc"})
        assert timeout == _DEFAULT_TIMEOUT

    def test_bad_retries_falls_back_to_default(self):
        _, retries = _resolve_resilience({"max_retries": "not-a-number"})
        assert retries == _DEFAULT_MAX_RETRIES

    def test_timeout_clamped_to_at_least_one(self):
        # A timeout of 0 would fail every call immediately.
        timeout, _ = _resolve_resilience({"request_timeout": 0})
        assert timeout == 1

    def test_negative_timeout_clamped_to_one(self):
        timeout, _ = _resolve_resilience({"request_timeout": -5})
        assert timeout == 1

    def test_retries_zero_is_preserved(self):
        # 0 is the documented disable switch — must NOT be clamped up.
        _, retries = _resolve_resilience({"max_retries": 0})
        assert retries == 0

    def test_negative_retries_clamped_to_zero(self):
        _, retries = _resolve_resilience({"max_retries": -3})
        assert retries == 0


# ── _get_session ───────────────────────────────────────────────────────────


class TestGetSession:

    def test_returns_session_with_no_retry_adapter_when_disabled(self):
        sess = _get_session(0)
        # When retries are disabled we leave the default adapter untouched.
        for adapter in sess.adapters.values():
            # urllib3 default is 0 retries; either way, no Retry object mounted.
            assert not isinstance(adapter.max_retries, Retry) or adapter.max_retries.total == 0

    def test_mounts_retry_adapter_on_both_schemes(self):
        sess = _get_session(3)
        for scheme in ("http://", "https://"):
            adapter = sess.get_adapter(scheme + "example.com")
            assert isinstance(adapter.max_retries, Retry)

    def test_retry_config_matches_contract(self):
        sess = _get_session(3)
        retry: Retry = sess.get_adapter("https://example.com").max_retries
        assert retry.total == 3
        assert retry.connect == 3
        assert retry.read == 3
        assert retry.status == 3
        # Must retry on rate-limit and 5xx; never on 4xx (other than 429).
        assert set(retry.status_forcelist) == {429, 500, 502, 503, 504}
        assert "POST" in retry.allowed_methods
        assert "GET" in retry.allowed_methods
        assert retry.backoff_factor == 0.5
        assert retry.respect_retry_after_header is True
        # raise_on_status=False lets caller see the final response after retries.
        assert retry.raise_on_status is False

    def test_sessions_are_cached_per_retry_count(self):
        s1 = _get_session(3)
        s2 = _get_session(3)
        assert s1 is s2, "Same max_retries should reuse the cached Session"

    def test_different_retry_counts_get_different_sessions(self):
        assert _get_session(3) is not _get_session(5)


# ── RequestHandler.send_request ────────────────────────────────────────────


class TestSendRequest:

    def _auth(self):
        auth = MagicMock()
        auth.authenticate_request.side_effect = lambda method, url, headers, body: headers
        auth.get_request_kwargs.return_value = {}
        return auth

    def test_send_request_uses_default_timeout_when_no_config(self):
        auth = self._auth()
        fake_session = MagicMock()
        fake_session.post.return_value = MagicMock(status_code=200)
        with patch.object(request_handler, "_get_session", return_value=fake_session) as gs:
            RequestHandler.send_request({"x": 1}, "https://api/test", auth)
        gs.assert_called_once_with(_DEFAULT_MAX_RETRIES)
        _, kwargs = fake_session.post.call_args
        assert kwargs["timeout"] == _DEFAULT_TIMEOUT

    def test_send_request_honors_config_timeout_and_retries(self):
        auth = self._auth()
        fake_session = MagicMock()
        fake_session.post.return_value = MagicMock(status_code=200)
        config = {"request_timeout": 7, "max_retries": 2}
        with patch.object(request_handler, "_get_session", return_value=fake_session) as gs:
            RequestHandler.send_request({"x": 1}, "https://api/test", auth, config)
        gs.assert_called_once_with(2)
        _, kwargs = fake_session.post.call_args
        assert kwargs["timeout"] == 7

    def test_send_request_passes_auth_kwargs_through(self):
        # e.g. mTLS cert tuple flows via get_request_kwargs() — must reach post().
        auth = self._auth()
        auth.get_request_kwargs.return_value = {"cert": ("/c.pem", "/k.pem"), "verify": "/ca.pem"}
        fake_session = MagicMock()
        fake_session.post.return_value = MagicMock(status_code=200)
        with patch.object(request_handler, "_get_session", return_value=fake_session):
            RequestHandler.send_request({"x": 1}, "https://api/test", auth)
        _, kwargs = fake_session.post.call_args
        assert kwargs["cert"] == ("/c.pem", "/k.pem")
        assert kwargs["verify"] == "/ca.pem"

    def test_send_request_lets_caller_see_final_response(self):
        # If urllib3 exhausts retries the caller should still get the Response
        # (raise_on_status=False) — sanity-check that send_request returns it.
        auth = self._auth()
        fake_response = MagicMock(status_code=503)
        fake_session = MagicMock()
        fake_session.post.return_value = fake_response
        with patch.object(request_handler, "_get_session", return_value=fake_session):
            resp = RequestHandler.send_request({"x": 1}, "https://api/test", auth)
        assert resp is fake_response
