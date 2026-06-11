"""Unit tests for auth provider abstraction (PTY-151133)."""

import os
from unittest.mock import patch, MagicMock
import pytest

from appython.service.auth_provider import (
    AuthProvider,
    CognitoAuthProvider,
    AWSIAMAuthProvider,
    BearerTokenAuthProvider,
    NoneAuthProvider,
    MTLSAuthProvider,
)
from appython.utils.exceptions import InitializationError

pytestmark = pytest.mark.migration


# ──────────────────────────────────────────────────────────────
# CognitoAuthProvider
# ──────────────────────────────────────────────────────────────

class TestCognitoAuthProvider:

    def _make_config(self, **overrides):
        defaults = {
            "de_email": "test@example.com",
            "de_password": "password123",
            "de_api_key": "test-api-key",
            "protect_host": "https://api.developer-edition.protegrity.com",
        }
        defaults.update(overrides)
        return defaults

    @patch("appython.service.auth_provider.http_requests.post")
    def test_initialize_success(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jwt_token": "mock-jwt-token"}
        )
        provider = CognitoAuthProvider(self._make_config())
        provider.initialize()
        assert provider._jwt_token == "mock-jwt-token"

    @patch("appython.service.auth_provider.http_requests.post")
    def test_initialize_calls_login_endpoint(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jwt_token": "tok"}
        )
        provider = CognitoAuthProvider(self._make_config())
        provider.initialize()
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert call_url == "https://api.developer-edition.protegrity.com/auth/login"

    def test_initialize_missing_email(self):
        provider = CognitoAuthProvider(self._make_config(de_email=None))
        with pytest.raises(InitializationError):
            provider.initialize()

    def test_initialize_missing_password(self):
        provider = CognitoAuthProvider(self._make_config(de_password=None))
        with pytest.raises(InitializationError):
            provider.initialize()

    def test_initialize_missing_api_key(self):
        provider = CognitoAuthProvider(self._make_config(de_api_key=None))
        with pytest.raises(InitializationError):
            provider.initialize()

    @patch("appython.service.auth_provider.http_requests.post")
    def test_initialize_login_failure(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=401,
            json=lambda: {"error": "Invalid credentials"}
        )
        provider = CognitoAuthProvider(self._make_config())
        with pytest.raises(InitializationError):
            provider.initialize()

    @patch("appython.service.auth_provider.http_requests.post")
    def test_authenticate_request_adds_headers(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"jwt_token": "jwt123"}
        )
        provider = CognitoAuthProvider(self._make_config())
        provider.initialize()

        headers = {"Content-Type": "application/json"}
        result = provider.authenticate_request("POST", "http://api/v1/protect", headers, {})

        assert "x-api-key" in result
        assert result["x-api-key"] == "test-api-key"
        assert "Authorization" in result
        assert result["Authorization"] == "jwt123"


# ──────────────────────────────────────────────────────────────
# AWSIAMAuthProvider
# ──────────────────────────────────────────────────────────────

try:
    import botocore
    _has_botocore = True
except ImportError:
    _has_botocore = False


@pytest.mark.skipif(not _has_botocore, reason="botocore not installed")
class TestAWSIAMAuthProvider:

    def _make_config(self, **overrides):
        defaults = {
            "protect_host": "https://abc123.execute-api.us-east-1.amazonaws.com/pty",
        }
        defaults.update(overrides)
        return defaults

    @patch("botocore.session.get_session")
    def test_initialize_success(self, mock_get_session):
        mock_session = MagicMock()
        mock_creds = MagicMock()
        mock_creds.get_frozen_credentials.return_value = mock_creds
        mock_session.get_credentials.return_value = mock_creds
        mock_get_session.return_value = mock_session

        provider = AWSIAMAuthProvider(self._make_config())
        provider.initialize()
        assert provider._credentials is not None

    @patch("botocore.session.get_session")
    def test_initialize_no_credentials(self, mock_get_session):
        mock_session = MagicMock()
        mock_session.get_credentials.return_value = None
        mock_get_session.return_value = mock_session

        provider = AWSIAMAuthProvider(self._make_config())
        with pytest.raises(InitializationError, match="AWS credentials not found"):
            provider.initialize()

    def test_region_extraction_from_url(self):
        provider = AWSIAMAuthProvider(self._make_config(
            protect_host="https://abc.execute-api.eu-west-1.amazonaws.com/prod"
        ))
        assert provider._region == "eu-west-1"

    def test_region_fallback_to_env(self):
        with patch.dict(os.environ, {"AWS_DEFAULT_REGION": "ap-southeast-1"}):
            provider = AWSIAMAuthProvider(self._make_config(protect_host="https://internal.corp.com/api"))
            assert provider._region == "ap-southeast-1"

    @patch("botocore.session.get_session")
    @patch("botocore.auth.SigV4Auth")
    @patch("botocore.awsrequest.AWSRequest")
    def test_authenticate_request_signs(self, mock_aws_req, mock_sigv4, mock_get_session):
        # Setup credentials
        mock_session = MagicMock()
        mock_creds = MagicMock()
        mock_creds.get_frozen_credentials.return_value = mock_creds
        mock_session.get_credentials.return_value = mock_creds
        mock_get_session.return_value = mock_session

        # Setup signed request mock
        mock_request_instance = MagicMock()
        mock_request_instance.headers = {
            "Authorization": "AWS4-HMAC-SHA256 Credential=...",
            "X-Amz-Date": "20260520T000000Z",
        }
        mock_aws_req.return_value = mock_request_instance

        provider = AWSIAMAuthProvider(self._make_config())
        provider.initialize()

        headers = {"Content-Type": "application/json"}
        result = provider.authenticate_request(
            "POST", "https://abc.execute-api.us-east-1.amazonaws.com/pty/v1/protect",
            headers, {"user": "test"}
        )

        assert "Authorization" in result
        assert "AWS4" in result["Authorization"]


# ──────────────────────────────────────────────────────────────
# BearerTokenAuthProvider
# ──────────────────────────────────────────────────────────────

class TestBearerTokenAuthProvider:

    def test_static_token_mode(self):
        config = {"static_token": "my-static-token", "token_endpoint": None,
                  "client_id": None, "client_secret": None}
        provider = BearerTokenAuthProvider(config)
        provider.initialize()
        assert provider._access_token == "my-static-token"

    def test_static_token_authenticate_request(self):
        config = {"static_token": "tok123", "token_endpoint": None,
                  "client_id": None, "client_secret": None}
        provider = BearerTokenAuthProvider(config)
        provider.initialize()

        headers = {}
        result = provider.authenticate_request("POST", "http://api/v1/protect", headers, {})
        assert result["Authorization"] == "Bearer tok123"

    @patch("appython.service.auth_provider.http_requests.post")
    def test_oauth2_client_credentials_flow(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "oauth-token-abc"}
        )
        config = {
            "static_token": None,
            "token_endpoint": "https://auth.example.com/oauth/token",
            "client_id": "my-client-id",
            "client_secret": "my-client-secret",
        }
        provider = BearerTokenAuthProvider(config)
        provider.initialize()

        assert provider._access_token == "oauth-token-abc"
        mock_post.assert_called_once()

    @patch("appython.service.auth_provider.http_requests.post")
    def test_oauth2_token_fetch_failure(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=400,
            text="invalid_client"
        )
        config = {
            "static_token": None,
            "token_endpoint": "https://auth.example.com/oauth/token",
            "client_id": "bad-client",
            "client_secret": "bad-secret",
        }
        provider = BearerTokenAuthProvider(config)
        with pytest.raises(InitializationError, match="Failed to fetch OAuth2 token"):
            provider.initialize()

    def test_missing_token_endpoint_and_static(self):
        config = {"static_token": None, "token_endpoint": None,
                  "client_id": None, "client_secret": None}
        provider = BearerTokenAuthProvider(config)
        with pytest.raises(InitializationError, match="PTY_STATIC_TOKEN"):
            provider.initialize()


# ──────────────────────────────────────────────────────────────
# NoneAuthProvider
# ──────────────────────────────────────────────────────────────

class TestNoneAuthProvider:

    def test_no_headers_added(self):
        provider = NoneAuthProvider({})
        headers = {"Content-Type": "application/json"}
        result = provider.authenticate_request("POST", "http://api/v1/protect", headers, {})
        assert result == {"Content-Type": "application/json"}

    def test_initialize_noop(self):
        provider = NoneAuthProvider({})
        provider.initialize()  # Should not raise


# ──────────────────────────────────────────────────────────────
# MTLSAuthProvider
# ──────────────────────────────────────────────────────────────

class TestMTLSAuthProvider:

    def test_initialize_success(self):
        config = {"client_cert": "/path/cert.pem", "client_key": "/path/key.pem", "ca_cert": "/path/ca.pem"}
        provider = MTLSAuthProvider(config)
        provider.initialize()

    def test_initialize_missing_cert(self):
        config = {"client_cert": None, "client_key": "/path/key.pem", "ca_cert": None}
        provider = MTLSAuthProvider(config)
        with pytest.raises(InitializationError, match="PTY_CLIENT_CERT"):
            provider.initialize()

    def test_initialize_missing_key(self):
        config = {"client_cert": "/path/cert.pem", "client_key": None, "ca_cert": None}
        provider = MTLSAuthProvider(config)
        with pytest.raises(InitializationError, match="PTY_CLIENT_CERT"):
            provider.initialize()

    def test_authenticate_request_no_header_changes(self):
        config = {"client_cert": "/path/cert.pem", "client_key": "/path/key.pem", "ca_cert": None}
        provider = MTLSAuthProvider(config)
        headers = {"Content-Type": "application/json"}
        result = provider.authenticate_request("POST", "http://api/v1/protect", headers, {})
        assert result == {"Content-Type": "application/json"}

    def test_get_request_kwargs_with_ca(self):
        config = {"client_cert": "/cert.pem", "client_key": "/key.pem", "ca_cert": "/ca.pem"}
        provider = MTLSAuthProvider(config)
        kwargs = provider.get_request_kwargs()
        assert kwargs["cert"] == ("/cert.pem", "/key.pem")
        assert kwargs["verify"] == "/ca.pem"

    def test_get_request_kwargs_without_ca(self):
        config = {"client_cert": "/cert.pem", "client_key": "/key.pem", "ca_cert": None}
        provider = MTLSAuthProvider(config)
        kwargs = provider.get_request_kwargs()
        assert kwargs["cert"] == ("/cert.pem", "/key.pem")
        assert "verify" not in kwargs
