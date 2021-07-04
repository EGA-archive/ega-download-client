from unittest import mock

import pytest

import pyega3.pyega3 as pyega3
from pyega3.credentials import Credentials


@mock.patch("pyega3.pyega3.download_file_retry")
def test_calls_download_for_every_file_in_dataset(mocked_dfr, mock_data_server, dataset_with_files, mock_server_config,
                                                  mock_auth_client):
    num_connections = 5

    pyega3.download_dataset(mock_server_config, mock_auth_client, dataset_with_files.id, num_connections, None, None, 5,
                            5, Credentials())

    assert len(dataset_with_files.files) == mocked_dfr.call_count
    mocked_dfr.assert_has_calls(
        [mock.call(mock_auth_client, f['fileId'], f['displayFileName'], f['fileName'], f['fileSize'],
                   f['unencryptedChecksum'], num_connections, None, None, 5, 5, mock_server_config, None) for f in
         dataset_with_files.files])


@mock.patch("pyega3.pyega3.download_file_retry")
def test_only_download_available_files(mocked_dfr, mock_server_config, mock_data_server, dataset_with_files,
                                       mock_auth_client):
    num_connections = 5

    mock_data_server.files[dataset_with_files.files[0].get("fileId")] = dataset_with_files.files[0] = {
        "fileStatus": "not available"
    }

    pyega3.download_dataset(mock_server_config, mock_auth_client, dataset_with_files.id, num_connections, None, None, 5,
                            5, Credentials())

    assert len(dataset_with_files.files) - 1 == mocked_dfr.call_count
    mocked_dfr.assert_has_calls(
        [mock.call(mock_auth_client, f['fileId'], f['displayFileName'], f['fileName'], f['fileSize'],
                   f['unencryptedChecksum'], num_connections, None, None, 5, 5, mock_server_config, None) for f in
         dataset_with_files.files if f['fileStatus'] == "available"])


def test_no_error_if_md5_mismatch(mock_server_config, mock_data_server, dataset_with_files, mock_auth_client):
    def dfr_throws(p1, p2, p3, p4, p5, p6): raise Exception("bad MD5")

    with mock.patch("pyega3.pyega3.download_file_retry", dfr_throws):
        pyega3.download_dataset(mock_server_config, mock_auth_client, dataset_with_files.id, 1, None, None, 5, 5,
                                Credentials())


def test_download_unknown_dataset_does_not_call_download_file_retry(mock_server_config, mock_data_server,
                                                                    mock_auth_client):
    with mock.patch("pyega3.pyega3.download_file_retry") as mocked_dfr:
        bad_dataset = "EGAD00000000666"
        pyega3.download_dataset(mock_server_config, mock_auth_client, bad_dataset, 1, None, None, 5, 5, Credentials())
        assert 0 == mocked_dfr.call_count


def test_download_legacy_dataset(mock_server_config, mock_auth_client):
    with pytest.raises(SystemExit):
        pyega3.download_dataset(mock_server_config, mock_auth_client, "EGAD00000000003", "1", "output_dir",
                                "genomic_range_args")
