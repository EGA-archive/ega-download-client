import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
from urllib import parse
from urllib.parse import urljoin

import pytest
import requests
import responses

import tests.unit.conftest as common
from pyega3.libs.auth_client import AuthClient, TOKEN_REFRESH_MAX_ATTEMPTS
from pyega3.libs.credentials import Credentials
from pyega3.libs.error import AuthenticationError
from pyega3 import pyega3 as cli


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


def test_bad_openid_credentials_raise_authentication_error(mock_openid_server, mock_server_config):
    bad_credentials = Credentials(username=common.rand_str(), password=common.rand_str())
    auth_server = AuthClient(mock_openid_server.url, mock_server_config.client_secret, {})
    auth_server.credentials = bad_credentials
    with pytest.raises(AuthenticationError, match="Authentication rejected"):
        token = auth_server.token


def test_concurrent_token_refresh_uses_one_authentication_request(mock_server_config):
    credentials = Credentials(username="test-user", password="test-password")
    auth_server = AuthClient(mock_server_config.url_auth, mock_server_config.client_secret, {})
    auth_server.credentials = credentials
    response = mock.Mock(status_code=200)
    response.json.return_value = {'access_token': 'refreshed-token'}

    def delayed_response(*_args, **_kwargs):
        time.sleep(0.05)
        return response

    with mock.patch("pyega3.libs.auth_client.requests.post", side_effect=delayed_response) as post:
        with ThreadPoolExecutor(max_workers=10) as executor:
            tokens = list(executor.map(lambda _: auth_server.token, range(10)))

    assert tokens == ['refreshed-token'] * 10
    assert post.call_count == 1


def test_token_refresh_retries_transient_network_failures(mock_server_config):
    credentials = Credentials(username="test-user", password="test-password")
    auth_server = AuthClient(mock_server_config.url_auth, mock_server_config.client_secret, {})
    auth_server.credentials = credentials
    response = mock.Mock(status_code=200)
    response.json.return_value = {'access_token': 'refreshed-token'}
    failures = [requests.exceptions.ConnectTimeout("timeout")] * (TOKEN_REFRESH_MAX_ATTEMPTS - 1)

    with mock.patch("pyega3.libs.auth_client.requests.post", side_effect=failures + [response]) as post, \
            mock.patch("pyega3.libs.auth_client.time.sleep") as sleep:
        assert auth_server.token == 'refreshed-token'

    assert post.call_count == TOKEN_REFRESH_MAX_ATTEMPTS
    assert sleep.call_args_list == [mock.call(1), mock.call(2)]


def test_concurrent_workers_share_failed_token_refresh(mock_server_config):
    credentials = Credentials(username="test-user", password="test-password")
    auth_server = AuthClient(mock_server_config.url_auth, mock_server_config.client_secret, {})
    auth_server.credentials = credentials
    release_refresh = threading.Event()

    def failed_response(*_args, **_kwargs):
        release_refresh.wait(timeout=5)
        raise requests.exceptions.ConnectTimeout("timeout")

    with mock.patch("pyega3.libs.auth_client.requests.post", side_effect=failed_response) as post, \
            mock.patch("pyega3.libs.auth_client.time.sleep"):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(lambda: auth_server.token) for _ in range(10)]
            deadline = time.time() + 5
            while auth_server._token_refresh_waiters < 9 and time.time() < deadline:
                time.sleep(0.005)
            assert auth_server._token_refresh_waiters == 9
            release_refresh.set()

        for future in futures:
            with pytest.raises(AuthenticationError, match="unavailable after 3 attempts"):
                future.result()

    assert post.call_count == TOKEN_REFRESH_MAX_ATTEMPTS

    response = mock.Mock(status_code=200)
    response.json.return_value = {'access_token': 'recovered-token'}
    with mock.patch("pyega3.libs.auth_client.requests.post", return_value=response):
        assert auth_server.token == 'recovered-token'


def test_authentication_service_error_is_not_reported_as_bad_credentials(mock_server_config):
    credentials = Credentials(username="test-user", password="test-password")
    auth_server = AuthClient(mock_server_config.url_auth, mock_server_config.client_secret, {})
    auth_server.credentials = credentials
    response = mock.Mock(status_code=503)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=response)

    with mock.patch("pyega3.libs.auth_client.requests.post", return_value=response) as post, \
            mock.patch("pyega3.libs.auth_client.time.sleep") as sleep:
        with pytest.raises(AuthenticationError, match="service failed with HTTP 503 after 3 attempts"):
            token = auth_server.token

    assert post.call_count == TOKEN_REFRESH_MAX_ATTEMPTS
    assert sleep.call_args_list == [mock.call(1), mock.call(2)]


def test_cli_maps_authentication_error_to_failure_exit_code():
    with mock.patch.object(cli, "_main", side_effect=AuthenticationError("authentication failed")):
        assert cli.main() == 1


def test_get_user_id_from_openid_server(mock_requests, mock_openid_server, mock_server_config):
    user_id = common.rand_str()
    auth_server = AuthClient(mock_server_config.url_auth, mock_server_config.client_secret, {})
    good_credentials = Credentials(username=mock_openid_server.username, password=mock_openid_server.password)
    auth_server.credentials = good_credentials
    user_info_url = urljoin(mock_server_config.url_auth, 'userinfo')
    mock_requests.add(responses.POST, user_info_url, body=json.dumps({'sub': user_id}), status=200)
    assert auth_server.user_id == user_id
