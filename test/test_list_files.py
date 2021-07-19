import pytest
import requests

import test.conftest as common
from pyega3.libs.data_set import DataSet


def test_list_all_files_in_dataset(dataset_with_files, mock_data_client):
    resp_json = DataSet(mock_data_client, dataset_with_files.id).list_files()

    assert len(resp_json) == 2
    assert resp_json[0].id == dataset_with_files.files[0]['fileId']
    assert resp_json[1].id == dataset_with_files.files[1]['fileId']


def test_error_with_bad_token(mock_data_server, dataset_with_files, mock_server_config, mock_data_client):
    mock_data_client.auth_client = common.MockAuthClient(common.rand_str())
    with pytest.raises(requests.exceptions.HTTPError):
        DataSet(mock_data_client, dataset_with_files.id).list_files()


def test_exit_with_unknown_dataset(mock_data_client, dataset_with_files):
    bad_dataset = common.rand_str()
    with pytest.raises(SystemExit):
        DataSet(mock_data_client, bad_dataset).list_files()


def test_exit_with_legacy_dataset(mock_data_client):
    with pytest.raises(SystemExit):
        DataSet(mock_data_client, "EGAD00000000003").list_files()


def test_exit_when_no_file_in_dataset(empty_dataset, mock_data_client):
    with pytest.raises(SystemExit):
        DataSet(mock_data_client, empty_dataset.id).list_files()
