from unittest import mock

import pytest

import pyega3.pyega3 as pyega3


@mock.patch("pyega3.pyega3.download_file_retry")
def test_calls_download_for_every_file_in_dataset(mocked_dfr, mock_data_server, dataset_with_files):
    with mock.patch("pyega3.pyega3.get_token", lambda _: mock_data_server.token):
        creds = {}
        num_connections = 5

        pyega3.download_dataset(creds, dataset_with_files.id, num_connections, None, None, None, 5, 5)

        assert len(dataset_with_files.files) == mocked_dfr.call_count
        mocked_dfr.assert_has_calls(
            [mock.call(creds, f['fileId'], f['displayFileName'], f['fileName'], f['fileSize'],
                       f['unencryptedChecksum'], num_connections, None, None, None, 5, 5) for f in
             dataset_with_files.files])


@mock.patch("pyega3.pyega3.download_file_retry")
def test_only_download_available_files(mocked_dfr, mock_data_server, dataset_with_files):
    with mock.patch("pyega3.pyega3.get_token", lambda _: mock_data_server.token):
        creds = {}
        num_connections = 5

        mock_data_server.files[dataset_with_files.files[0].get("fileId")] = dataset_with_files.files[0] = {
            "fileStatus": "not available"
        }

        pyega3.download_dataset(creds, dataset_with_files.id, num_connections, None, None, None, 5, 5)

        assert len(dataset_with_files.files) - 1 == mocked_dfr.call_count
        mocked_dfr.assert_has_calls(
            [mock.call(creds, f['fileId'], f['displayFileName'], f['fileName'], f['fileSize'],
                       f['unencryptedChecksum'], num_connections, None, None, None, 5, 5) for f in
             dataset_with_files.files if f['fileStatus'] == "available"])


def test_no_error_if_md5_mismatch(mock_data_server, dataset_with_files):
    def dfr_throws(p1, p2, p3, p4, p5, p6): raise Exception("bad MD5")

    with mock.patch("pyega3.pyega3.get_token", lambda _: mock_data_server.token):
        with mock.patch("pyega3.pyega3.download_file_retry", dfr_throws):
            pyega3.download_dataset({}, dataset_with_files.id, 1, None, None, None, 5, 5)


def test_download_unknown_dataset_does_not_call_download_file_retry(mock_data_server):
    with mock.patch("pyega3.pyega3.download_file_retry") as mocked_dfr:
        with mock.patch("pyega3.pyega3.get_token", lambda _: mock_data_server.token):
            bad_dataset = "EGAD00000000666"
            pyega3.download_dataset({}, bad_dataset, 1, None, None, None, 5, 5)
            assert 0 == mocked_dfr.call_count


def test_download_legacy_dataset():
    with pytest.raises(SystemExit):
        pyega3.download_dataset("credentials", "EGAD00000000003", "1", "key", "output_dir",
                                "genomic_range_args")
