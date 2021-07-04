import responses

import pyega3.pyega3 as pyega3


def test_when_ipinfo_is_blocked_return_unknown(mock_requests):
    endpoint = 'https://ipinfo.io/json'
    mock_requests.add(responses.GET, endpoint, status=403)

    resp_ip = pyega3.get_client_ip()

    assert resp_ip == 'Unknown'
