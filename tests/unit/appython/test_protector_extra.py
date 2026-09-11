import os
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

from appython import Protector, CheckAccessType
from appython.utils.exceptions import ProtectorError, InitializationError, InvalidSessionError, ReprotectError


@pytest.fixture(autouse=True)
def setup_auth_env():
    with patch.dict(os.environ, {"PTY_AUTH_MODE": "none"}):
        yield


def test_protector_versions_and_lifecycle():
    p = Protector()
    assert p.get_version() == "1.2.2"
    assert "1.2.2" in p.get_version_ex()
    assert p.terminate() is True

    with pytest.raises(ProtectorError):
        p.create_session("")


def test_session_init_and_validation():
    p = Protector()
    session = p.create_session("alice", timeout=10)
    assert repr(session) == "Session(user=alice)"
    assert session.check_access("name", CheckAccessType.PROTECT) is True
    assert session.flush_audits() is True

    with pytest.raises(ValueError):
        p.create_session("alice", timeout="invalid_timeout")

    # Timeout expiry test
    session._timestamp = datetime.now() - timedelta(minutes=20)
    with pytest.raises(InvalidSessionError):
        session.protect("test", "name")


def test_session_context_manager():
    p = Protector()
    with p.create_session("bob", timeout=5) as session:
        assert session._user == "bob"
    assert session._closed is True


def test_session_atexit_flush():
    p = Protector()
    with patch.dict(os.environ, {"PTY_STATS": "true"}):
        session = p.create_session("charlie", timeout=5)
        with patch("appython.protector.flush_stats") as mock_flush:
            session._atexit_flush()
            mock_flush.assert_called_once()
            assert session._closed is True


def test_session_legacy_authenticate():
    p = Protector()
    session = p.create_session("david", timeout=5)

    # Missing email / password
    with patch.dict(os.environ, {"DEV_EDITION_EMAIL": "", "DEV_EDITION_PASSWORD": ""}):
        with pytest.raises(InitializationError, match="Both DEV_EDITION_EMAIL"):
            session.authenticate()

    # Missing API key
    with patch.dict(os.environ, {
        "DEV_EDITION_EMAIL": "e@test.com",
        "DEV_EDITION_PASSWORD": "pass",
        "DEV_EDITION_API_KEY": "",
    }):
        with pytest.raises(InitializationError, match="DEV_EDITION_API_KEY must be provided"):
            session.authenticate()

    # Auth failure from endpoint
    mock_resp = MagicMock(status_code=401)
    mock_resp.json.return_value = {"error": "Invalid creds"}
    with patch.dict(os.environ, {
        "DEV_EDITION_EMAIL": "e@test.com",
        "DEV_EDITION_PASSWORD": "pass",
        "DEV_EDITION_API_KEY": "key",
    }), patch("appython.service.auth_token_provider.AuthTokenProvider.get_jwt_token", return_value=mock_resp):
        with pytest.raises(InitializationError, match="Invalid creds"):
            session.authenticate()

    # Auth success from endpoint
    mock_resp_ok = MagicMock(status_code=200)
    mock_resp_ok.json.return_value = {"jwt_token": "token123"}
    with patch.dict(os.environ, {
        "DEV_EDITION_EMAIL": "e@test.com",
        "DEV_EDITION_PASSWORD": "pass",
        "DEV_EDITION_API_KEY": "key",
    }), patch("appython.service.auth_token_provider.AuthTokenProvider.get_jwt_token", return_value=mock_resp_ok):
        api_key, token = session.authenticate()
        assert api_key == "key"
        assert token == "token123"


@patch("appython.protector.InputPreprocessor")
@patch("appython.protector.PayloadBuilder")
@patch("appython.protector.RequestHandler")
@patch("appython.protector.ResponseHandler")
def test_session_reprotect(mock_resp_h, mock_req_h, mock_pb, mock_ip):
    mock_ip.convert_input_to_string.return_value = {"input_datatype": "string"}
    mock_ip.validate_parameters.return_value = {}
    mock_pb.build_api_request.return_value = ({}, {}, "http://url")
    mock_req_h.send_request.return_value = MagicMock()
    mock_resp_h.process.return_value = "reprotected_value"

    p = Protector()
    session = p.create_session("eve", timeout=5)
    res = session.reprotect("data", "old_de", "new_de")
    assert res == "reprotected_value"

    # Reprotect error
    mock_resp_h.process.side_effect = Exception("Reprotect failed")
    with pytest.raises(ReprotectError):
        session.reprotect("data", "old_de", "new_de")
