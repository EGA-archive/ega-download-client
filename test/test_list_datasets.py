import pytest
import requests

import pyega3.pyega3 as pyega3
import test.conftest as common


def test_list_all_datasets(mock_data_server, mock_server_config):
    mock_data_server.dataset_files = {'EGAD000000001': None, 'EGAD000000002': None, 'EGAD000000003': None}
    resp_json = pyega3.api_list_authorized_datasets(mock_data_server.token, mock_server_config)
    assert len(resp_json) == 3
    assert resp_json[0] == mock_data_server.all_datasets[0]
    assert resp_json[1] == mock_data_server.all_datasets[1]
    assert resp_json[2] == mock_data_server.all_datasets[2]


def test_error_when_token_is_not_valid(mock_data_server, mock_server_config):
    with pytest.raises(requests.exceptions.HTTPError):
        pyega3.api_list_authorized_datasets(common.rand_str(), mock_server_config)


def test_exit_when_user_has_no_datasets(mock_data_server, mock_server_config):
    mock_data_server.dataset_files = None

    with pytest.raises(SystemExit):
        pyega3.api_list_authorized_datasets(mock_data_server.token, mock_server_config)
