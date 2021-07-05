import random
from unittest import mock

import pytest
import requests

import pyega3.pyega3 as pyega3
import test.conftest as common


def test_download_file_slice_downloads_correct_bytes_to_file(mock_data_server, random_binary_file):
    file_id = "EGAF1234"
    mock_data_server.file_content[file_id] = random_binary_file

    slice_start = random.randint(0, len(random_binary_file))
    slice_length = random.randint(0, len(random_binary_file) - slice_start)

    written_bytes = 0

    def mock_write(buf):
        nonlocal written_bytes
        buf_len = len(buf)
        expected_buf = random_binary_file[slice_start + written_bytes:slice_start + written_bytes + buf_len]
        assert expected_buf == buf
        written_bytes += buf_len

    file_name = common.rand_str()
    file_name_for_slice = file_name + '-from-' + str(slice_start) + '-len-' + str(slice_length) + '.slice'

    m_open = mock.mock_open()
    with mock.patch("builtins.open", m_open, create=True):
        with mock.patch("os.path.getsize", lambda path: written_bytes if path == file_name_for_slice else 0):
            m_open().write.side_effect = mock_write
            pyega3.download_file_slice(mock_data_server.url + "/files/" + file_id, mock_data_server.token, file_name,
                                       slice_start, slice_length)
            assert slice_length == written_bytes

    m_open.assert_called_with(file_name_for_slice, 'ba')


def test_error_when_bad_token(mock_data_server):
    file_id = "EGAF1234"
    bad_token = common.rand_str()
    with pytest.raises(requests.exceptions.HTTPError):
        pyega3.download_file_slice(mock_data_server.url + "/files/" + file_id, bad_token, common.rand_str(), 1, 10)


def test_error_when_bad_url():
    bad_url = "https://bad_test_server_url"
    with pytest.raises(requests.exceptions.ConnectionError):
        pyega3.download_file_slice(bad_url, common.rand_str(), common.rand_str(), 1, 10)


def test_error_when_start_is_negative():
    with pytest.raises(ValueError):
        pyega3.download_file_slice(common.rand_str(), common.rand_str(), common.rand_str(), -1, 1)


def test_error_when_end_is_negative():
    with pytest.raises(ValueError):
        pyega3.download_file_slice(common.rand_str(), common.rand_str(), common.rand_str(), 0, -1)
