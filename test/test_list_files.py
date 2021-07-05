import pytest
import requests

import pyega3.pyega3 as pyega3
import test.conftest as common


def test_list_all_files_in_dataset(dataset_with_files, mock_data_client):
    resp_json = pyega3.api_list_files_in_dataset(mock_data_client, dataset_with_files.id)

    assert len(resp_json) == 2
    assert resp_json[0] == dataset_with_files.files[0]
    assert resp_json[1] == dataset_with_files.files[1]


def test_error_with_bad_token(mock_data_server, dataset_with_files, mock_server_config, mock_data_client):
    mock_data_client.auth_client = common.MockAuthClient(common.rand_str())
    with pytest.raises(requests.exceptions.HTTPError):
        pyega3.api_list_files_in_dataset(mock_data_client, dataset_with_files.id)


def test_exit_with_unknown_dataset(mock_data_client, dataset_with_files):
    bad_dataset = common.rand_str()
    with pytest.raises(SystemExit):
        pyega3.api_list_files_in_dataset(mock_data_client, bad_dataset)


def test_exit_with_legacy_dataset(mock_data_client):
    with pytest.raises(SystemExit):
        pyega3.api_list_files_in_dataset(mock_data_client, "EGAD00000000003")


def test_exit_when_no_file_in_dataset(empty_dataset, mock_data_client):
    with pytest.raises(SystemExit):
        pyega3.api_list_files_in_dataset(mock_data_client, empty_dataset.id)
