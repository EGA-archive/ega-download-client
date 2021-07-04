import json
from urllib import parse

import pytest
import responses

import pyega3.pyega3 as pyega3
import test.conftest as common


@pytest.fixture
def mock_openid_server(mock_requests):
    class MockOpenIDServer:
        url = "https://mock.openid.server"
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


def test_get_token_from_openid_server(mock_openid_server):
    pyega3.URL_AUTH = mock_openid_server.url

    good_credentials = (mock_openid_server.username, mock_openid_server.password)
    resp_token = pyega3.get_token(good_credentials)
    assert resp_token == mock_openid_server.access_token


def test_bad_openid_credentials_exits(mock_openid_server):
    pyega3.URL_AUTH = mock_openid_server.url

    bad_credentials = (common.rand_str(), common.rand_str())
    with pytest.raises(SystemExit):
        pyega3.get_token(bad_credentials)
