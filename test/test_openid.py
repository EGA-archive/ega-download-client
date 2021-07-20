import json
from urllib import parse

import pytest
import responses

import test.conftest as common
from pyega3.libs.auth_client import AuthClient
from pyega3.libs.credentials import Credentials


@pytest.fixture
def mock_openid_server(mock_requests, mock_server_config):
    class MockOpenIDServer:
        url = mock_server_config.url_auth
        id_token = common.rand_str()
        access_token = common.rand_str()
        username = common.rand_str()
        password = common.rand_str()

        def __init__(self):
            mock_requests.add_callback(responses.POST,
                                       self.url,
                                       callback=self.request_callback,
                                       content_type='application/json')

        def request_callback(self, request):

            query = parse.parse_qs(request.body)
            if query['username'][0] == self.username and query['password'][0] == self.password:
                return (200, {}, json.dumps(
                    {"access_token": self.access_token, "id_token": self.id_token, "token_type": "Bearer",
                     "expires_in": 3600}))
            else:
                return 400, {}, json.dumps({"error_description": "Bad credentials", "error": "invalid_grant"})

    return MockOpenIDServer()


def test_get_token_from_openid_server(mock_openid_server, mock_server_config):
    good_credentials = Credentials(username=mock_openid_server.username, password=mock_openid_server.password)
    auth_server = AuthClient(mock_openid_server.url, mock_server_config.client_secret, {})
    auth_server.credentials = good_credentials
    assert auth_server.token == mock_openid_server.access_token


def test_bad_openid_credentials_exits(mock_openid_server, mock_server_config):
    bad_credentials = Credentials(username=common.rand_str(), password=common.rand_str())
    auth_server = AuthClient(mock_openid_server.url, mock_server_config.client_secret, {})
    auth_server.credentials = bad_credentials
    with pytest.raises(SystemExit):
        token = auth_server.token
