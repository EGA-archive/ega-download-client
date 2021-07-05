import unittest.mock
from unittest import mock

import pytest

import pyega3.pyega3 as pyega3


@mock.patch("pyega3.data_file.DataFile")
def test_calls_download_for_every_file_in_dataset(mocked_datafile, mock_data_server, dataset_with_files,
                                                  mock_server_config,
                                                  mock_auth_client, mock_data_client):
    num_connections = 5

    mock_files = [unittest.mock.MagicMock() for _ in range(len(dataset_with_files.files))]
    mocked_datafile.side_effect = mock_files

    pyega3.download_dataset(mock_data_client, dataset_with_files.id, num_connections, None, None, 5, 5)

    assert len(dataset_with_files.files) == mocked_datafile.call_count
    mocked_datafile.assert_has_calls(
        [mock.call(mock_data_client, f['fileId'], f['displayFileName'], f['fileName'], f['fileSize'],
                   f['unencryptedChecksum']) for f in dataset_with_files.files])
    for mock_file in mock_files:
        assert len(mock_file.method_calls) == 1
        assert mock_file.method_calls[0] == ('download_file_retry', (num_connections, None, None, 5, 5, None))


@mock.patch("pyega3.data_file.DataFile")
def test_only_download_available_files(mocked_datafile, mock_server_config, mock_data_server, dataset_with_files,
                                       mock_auth_client, mock_data_client):
    num_connections = 5

    mock_files = [unittest.mock.MagicMock() for _ in range(len(dataset_with_files.files) - 1)]
    mocked_datafile.side_effect = mock_files

    mock_data_server.files[dataset_with_files.files[0].get("fileId")] = dataset_with_files.files[0] = {
        "fileStatus": "not available"
    }

    pyega3.download_dataset(mock_data_client, dataset_with_files.id, num_connections, None, None, 5, 5)

    assert len(dataset_with_files.files) - 1 == mocked_datafile.call_count
    mocked_datafile.assert_has_calls(
        [mock.call(mock_data_client, f['fileId'], f['displayFileName'], f['fileName'], f['fileSize'],
                   f['unencryptedChecksum']) for f in dataset_with_files.files if f['fileStatus'] == "available"])
    for mock_file in mock_files:
        assert len(mock_file.method_calls) == 1
        assert mock_file.method_calls[0] == ('download_file_retry', (num_connections, None, None, 5, 5, None))


def test_no_error_if_md5_mismatch(mock_server_config, mock_data_server, dataset_with_files, mock_auth_client,
                                  mock_data_client):
    def dfr_throws(p1, p2, p3, p4, p5, p6): raise Exception("bad MD5")

    with mock.patch("pyega3.data_file.DataFile.download_file_retry", dfr_throws):
        pyega3.download_dataset(mock_data_client, dataset_with_files.id, 1, None, None, 5, 5)


def test_download_unknown_dataset_does_not_call_download_file_retry(mock_server_config, mock_data_server,
                                                                    mock_auth_client, mock_data_client):
    with mock.patch("pyega3.data_file.DataFile.download_file_retry") as mocked_dfr:
        bad_dataset = "EGAD00000000666"
        pyega3.download_dataset(mock_data_client, bad_dataset, 1, None, None, 5, 5)
        assert 0 == mocked_dfr.call_count


def test_download_legacy_dataset(mock_server_config, mock_auth_client, mock_data_client):
    with pytest.raises(SystemExit):
        pyega3.download_dataset(mock_data_client, "EGAD00000000003", "1", "output_dir", "genomic_range_args")
