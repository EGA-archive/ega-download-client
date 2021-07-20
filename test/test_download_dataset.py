import unittest.mock
from unittest import mock

import pytest

from pyega3.libs.data_file import DataFile
from pyega3.libs.data_set import DataSet


@mock.patch("pyega3.libs.data_file.DataFile")
def test_calls_download_for_every_file_in_dataset(mocked_datafile, mock_data_server, dataset_with_files,
                                                  mock_server_config,
                                                  mock_auth_client, mock_data_client):
    num_connections = 5

    mock_files = [unittest.mock.MagicMock() for _ in range(len(dataset_with_files.files))]
    for file in mock_files:
        file.status = "available"
    mocked_datafile.side_effect = mock_files

    dataset = DataSet(mock_data_client, dataset_with_files.id)
    dataset.download(num_connections, None, None, 5, 5)

    assert len(dataset_with_files.files) == mocked_datafile.call_count
    mocked_datafile.assert_has_calls(
        [mock.call(mock_data_client,
                   f['fileId'],
                   display_file_name=f['displayFileName'],
                   file_name=f['fileName'],
                   size=f['fileSize'],
                   unencrypted_checksum=f['unencryptedChecksum'],
                   status=f['fileStatus'])
         for f in dataset_with_files.files])

    for mock_file in mock_files:
        assert len(mock_file.method_calls) == 1
        assert mock_file.method_calls[0] == ('download_file_retry',
                                             (num_connections, None, None, 5, 5, DataFile.DEFAULT_SLICE_SIZE))


@mock.patch("pyega3.libs.data_file.DataFile")
def test_only_download_available_files(mocked_datafile, mock_server_config, mock_data_server, dataset_with_files,
                                       mock_auth_client, mock_data_client):
    num_connections = 5

    mock_files = [unittest.mock.MagicMock() for _ in range(len(dataset_with_files.files))]
    for file in mock_files:
        file.status = "available"
    mocked_datafile.side_effect = mock_files

    mock_data_server.files[dataset_with_files.files[0].get("fileId")] = dataset_with_files.files[0] = {
        "fileId": dataset_with_files.files[0].get("fileId"),
        "fileStatus": "not available"
    }
    mock_files[0].status = "not available"

    dataset = DataSet(mock_data_client, dataset_with_files.id)
    dataset.download(num_connections, None, None, 5, 5)

    assert len(dataset_with_files.files) == mocked_datafile.call_count
    mocked_datafile.assert_has_calls(
        [mock.call(mock_data_client, f['fileId'],
                   display_file_name=f.get('displayFileName'),
                   file_name=f.get('fileName'),
                   size=f.get('fileSize'),
                   unencrypted_checksum=f.get('unencryptedChecksum'),
                   status=f.get('fileStatus')) for f in dataset_with_files.files])

    # The first file was not available so it should not have been called
    assert len(mock_files[0].method_calls) == 0

    # The other files should all have been downloaded
    for mock_file in mock_files[1:]:
        assert len(mock_file.method_calls) == 1
        assert mock_file.method_calls[0] == ('download_file_retry',
                                             (num_connections, None, None, 5, 5, DataFile.DEFAULT_SLICE_SIZE))


def test_no_error_if_md5_mismatch(mock_server_config, mock_data_server, dataset_with_files, mock_auth_client,
                                  mock_data_client):
    def dfr_throws(p1, p2, p3, p4, p5, p6): raise Exception("bad MD5")

    with mock.patch("pyega3.libs.data_file.DataFile.download_file_retry", dfr_throws):
        dataset = DataSet(mock_data_client, dataset_with_files.id)
        dataset.download(1, None, None, 5, 5)


def test_download_unknown_dataset_does_not_call_download_file_retry(mock_server_config, mock_data_server,
                                                                    mock_auth_client, mock_data_client):
    with mock.patch("pyega3.libs.data_file.DataFile.download_file_retry") as mocked_dfr:
        bad_dataset = "EGAD00000000666"
        dataset = DataSet(mock_data_client, bad_dataset)
        dataset.download(1, None, None, 5, 5)
        assert 0 == mocked_dfr.call_count


def test_download_legacy_dataset(mock_server_config, mock_auth_client, mock_data_client):
    with pytest.raises(SystemExit):
        dataset = DataSet(mock_data_client, "EGAD00000000003")
        dataset.download(1, None, None, 5, 5)
