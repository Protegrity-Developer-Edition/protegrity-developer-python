import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from pty_migrate.ppc_client import PPCClient


@pytest.fixture
def client():
    return PPCClient("localhost", "admin", "password", port=443)


def test_auth_header_success(client):
    mock_resp = MagicMock(status_code=200)
    mock_resp.headers = {"pty_access_jwt_token": "token123"}
    with patch.object(client._session, "post", return_value=mock_resp):
        client.authenticate()
        assert client._access_token == "token123"
        assert client._session.headers["Authorization"] == "Bearer token123"


def test_auth_body_fallback_success(client):
    # Header fail, body succeed
    resp_hdr = MagicMock(status_code=404)
    resp_body = MagicMock(status_code=200)
    resp_body.json.return_value = {
        "accessToken": "bodytoken123",
        "refreshToken": "ref123",
        "expiresIn": 3600,
    }
    with patch.object(client._session, "post", side_effect=[resp_hdr, resp_body]):
        client.authenticate()
        assert client._access_token == "bodytoken123"
        assert client._refresh_token == "ref123"


def test_auth_failure_raises(client):
    resp_hdr = MagicMock(status_code=404)
    resp_body = MagicMock(status_code=401, text="Unauthorized")
    with patch.object(client._session, "post", side_effect=[resp_hdr, resp_body]):
        with pytest.raises(RuntimeError):
            client.authenticate()


def test_ensure_auth_and_refresh(client):
    client._access_token = "token"
    client._refresh_token = "ref"
    client._token_expiry = time.time() - 10  # expired
    client._refresh_expiry = time.time() + 1000

    resp = MagicMock(status_code=200)
    resp.json.return_value = {"accessToken": "newtoken", "expiresIn": 3600}
    with patch.object(client._session, "post", return_value=resp):
        client._ensure_auth()
        assert client._access_token == "newtoken"


def test_refresh_failure_falls_back_to_authenticate(client):
    client._access_token = "token"
    client._refresh_token = "ref"
    client._token_expiry = time.time() - 10
    client._refresh_expiry = time.time() + 1000

    resp_refresh = MagicMock(status_code=401)
    with patch.object(client._session, "post", return_value=resp_refresh), \
         patch.object(client, "authenticate") as mock_auth:
        client._refresh()
        mock_auth.assert_called_once()


def test_post_resource_states(client):
    client._access_token = "valid_token"
    client._token_expiry = time.time() + 1000

    # 201 Created
    with patch.object(client._session, "post", return_value=MagicMock(status_code=201)):
        ok, _ = client.post_resource("datastores", {"name": "ds1"})
        assert ok is True

    # 409 Exists
    with patch.object(client._session, "post", return_value=MagicMock(status_code=409)):
        ok, _ = client.post_resource("datastores", {"name": "ds1"})
        assert ok is False

    # 400 Already exists body
    resp_400 = MagicMock(status_code=400, text="resource already exists")
    with patch.object(client._session, "post", return_value=resp_400):
        ok, _ = client.post_resource("datastores", {"name": "ds1"})
        assert ok is False

    # 500 error
    resp_500 = MagicMock(status_code=500)
    resp_500.raise_for_status.side_effect = requests.exceptions.HTTPError()
    with patch.object(client._session, "post", return_value=resp_500):
        with pytest.raises(requests.exceptions.HTTPError):
            client.post_resource("datastores", {"name": "ds1"})


def test_pim_init(client):
    client._access_token = "token"
    client._token_expiry = time.time() + 1000

    # Already initialized
    with patch.object(client, "is_pim_initialized", return_value=True):
        assert client.init_pim() is True

    # Needs init
    with patch.object(client, "is_pim_initialized", return_value=False), \
         patch.object(client, "_post", return_value=MagicMock(status_code=200)):
        assert client.init_pim() is True


def test_parse_list_response(client):
    # Non-200
    assert client._parse_list_response(MagicMock(status_code=500)) == []

    # 200 list
    resp_list = MagicMock(status_code=200)
    resp_list.json.return_value = [{"id": 1}]
    assert client._parse_list_response(resp_list) == [{"id": 1}]

    # 200 dict data
    resp_dict = MagicMock(status_code=200)
    resp_dict.json.return_value = {"data": [{"id": 2}]}
    assert client._parse_list_response(resp_dict) == [{"id": 2}]


def test_list_and_create_methods(client):
    client._access_token = "token"
    client._token_expiry = time.time() + 1000

    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = [{"name": "item"}]
    with patch.object(client._session, "get", return_value=mock_resp), \
         patch.object(client._session, "post", return_value=MagicMock(status_code=201)):
        assert client.list_datastores() == [{"name": "item"}]
        assert client.list_sources() == [{"name": "item"}]
        assert client.list_roles() == [{"name": "item"}]
        assert client.list_alphabets() == [{"name": "item"}]
        assert client.list_masks() == [{"name": "item"}]
        assert client.list_data_elements() == [{"name": "item"}]
        assert client.list_applications() == [{"name": "item"}]
        assert client.list_policies() == [{"name": "item"}]
        assert client.list_rules("1") == [{"name": "item"}]
        assert client.list_role_members("1") == [{"name": "item"}]
        assert client.list_export_keys("1") == [{"name": "item"}]

        assert client.create_datastore({"name": "d"})[0] is True
        assert client.create_source({"name": "s"})[0] is True
        assert client.create_role({"name": "r"})[0] is True
        assert client.create_alphabet({"name": "a"})[0] is True
        assert client.create_mask({"name": "m"})[0] is True
        assert client.create_data_element({"name": "de"})[0] is True
        assert client.create_application({"name": "app"})[0] is True
        assert client.create_policy({"name": "p"})[0] is True
        assert client.create_rule("1", {"name": "rule"})[0] is True
        assert client.add_members("1", [{"name": "u"}])[0] is True
        assert client.deploy("1")[0] is True


def test_user_management(client):
    client._access_token = "token"
    client._token_expiry = time.time() + 1000

    # list_users / user_exists
    mock_users_resp = MagicMock(status_code=200)
    mock_users_resp.json.return_value = [{"username": "alice"}]
    with patch.object(client._session, "get", return_value=mock_users_resp):
        assert client.user_exists("alice") is True
        assert client.user_exists("bob") is False

    # create_user 201
    with patch.object(client._session, "post", return_value=MagicMock(status_code=201)):
        ok, _ = client.create_user("bob", "secret")
        assert ok is True

    # create_user 409
    with patch.object(client._session, "post", return_value=MagicMock(status_code=409)):
        ok, _ = client.create_user("alice", "secret")
        assert ok is False

    # ensure_role_permissions
    with patch.object(client._session, "put", return_value=MagicMock(status_code=200)):
        assert client.ensure_role_permissions("admin", ["perm1"]) is True

    # re_authenticate
    with patch.object(client, "authenticate") as mock_auth:
        client.re_authenticate("new_user", "new_pass")
        assert client._user == "new_user"
        mock_auth.assert_called_once()
