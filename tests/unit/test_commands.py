import responses

from pyega3.libs.commands import execute_subcommand


def test_error_5xx(mock_data_client, mock_requests, mock_server_config, caplog):

    class Args:
        subcommand = "datasets"

    mock_requests.add(responses.GET, mock_server_config.url_api + "/metadata/datasets", status=503)

    try:
        execute_subcommand(Args(), mock_data_client)
    except SystemExit as sys_exit_error:
        assert sys_exit_error.code == 1

    errors = [m for m in caplog.records if m.levelname == "ERROR"]
    assert len(errors) == 1
    assert "error on the server" in errors[0].message


def test_error_too_many_requests(mock_data_client, mock_requests, mock_server_config, caplog):

    class Args:
        subcommand = "datasets"

    mock_requests.add(responses.GET, mock_server_config.url_api + "/metadata/datasets", status=429)

    try:
        execute_subcommand(Args(), mock_data_client)
    except SystemExit as sys_exit_error:
        assert sys_exit_error.code == 1

    errors = [m for m in caplog.records if m.levelname == "ERROR"]
    assert len(errors) == 1
    assert "too many requests" in errors[0].message
