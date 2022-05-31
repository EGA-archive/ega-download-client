import responses

from pyega3.libs.utils import get_client_ip


def test_when_ipinfo_is_blocked_return_unknown(mock_requests):
    endpoint = 'https://ipinfo.io/json'
    mock_requests.add(responses.GET, endpoint, status=403)

    resp_ip = get_client_ip()

    assert resp_ip == 'Unknown'
