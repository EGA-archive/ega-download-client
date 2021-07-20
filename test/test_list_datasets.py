import pytest
import requests

import test.conftest as common
from pyega3.libs.data_set import DataSet


def test_list_all_datasets(mock_data_server, mock_data_client):
    mock_data_server.dataset_files = {'EGAD000000001': None, 'EGAD000000002': None, 'EGAD000000003': None}
    resp_json = DataSet.list_authorized_datasets(mock_data_client)
    assert len(resp_json) == 3
    assert resp_json[0].id == mock_data_server.all_datasets[0]
    assert resp_json[1].id == mock_data_server.all_datasets[1]
    assert resp_json[2].id == mock_data_server.all_datasets[2]


def test_error_when_token_is_not_valid(mock_data_server, mock_data_client):
    mock_data_client.auth_client = common.MockAuthClient("invalid token")
    with pytest.raises(requests.exceptions.HTTPError):
        DataSet.list_authorized_datasets(mock_data_client)


def test_exit_when_user_has_no_datasets(mock_data_server, mock_data_client):
    mock_data_server.dataset_files = None

    with pytest.raises(SystemExit):
        DataSet.list_authorized_datasets(mock_data_client)
