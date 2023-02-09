import glob
import random
from collections import namedtuple
from unittest import mock
from unittest.mock import Mock, patch

import pytest
import requests
import os

from urllib3.exceptions import NewConnectionError

import tests.unit.conftest as common
from pyega3.libs.data_file import DataFile


@pytest.fixture
def slice_file(random_binary_file):
    file_id = "EGAF1234"
    file_size = len(random_binary_file)
    slice_start = random.randint(0, file_size)
    slice_len = random.randint(0, file_size - slice_start)
    file_name = common.rand_str()
    file_name_for_slice = f'{file_name}-from-{slice_start}-len-{slice_len}.slice'
    SliceFile = namedtuple("SliceFile", "id original_file_size start length original_file_name file_name binary")
    return SliceFile(file_id, file_size, slice_start, slice_len, file_name, file_name_for_slice, random_binary_file)


def test_download_file_slice_downloads_correct_bytes_to_file(mock_data_server, slice_file, mock_data_client):
    mock_data_server.file_content[slice_file.id] = slice_file.binary
    file_name = common.rand_str()
    slice_temp_file_name = file_name + '-from-' + str(slice_file.start) + '-len-' + str(
        slice_file.length) + '.slice.tmp'
    file = DataFile(mock_data_client, slice_file.id)
    m_open = mock.mock_open()
    download_mock = SliceFileDownloadMock(slice_file)
    with mock.patch("builtins.open", m_open, create=True):
        with mock.patch("os.path.getsize",
                        lambda path: download_mock.written_bytes if path == slice_temp_file_name else 0):
            with mock.patch("os.rename"):
                m_open().write.side_effect = download_mock.write
                file.download_file_slice(file_name, slice_file.start, slice_file.length)
                assert slice_file.length == download_mock.written_bytes

    m_open.assert_called_with(slice_temp_file_name, 'ba')


def test_error_when_bad_token(mock_data_server, mock_data_client):
    file_id = "EGAF1234"
    bad_token = common.rand_str()
    mock_data_client.auth_client = common.MockAuthClient(bad_token)
    file = DataFile(mock_data_client, file_id)
    with pytest.raises(requests.exceptions.HTTPError):
        file.download_file_slice(common.rand_str(), 1, 10)


def test_error_when_bad_url(mock_data_client):
    file = DataFile(mock_data_client, "bad/url")
    with pytest.raises(NewConnectionError):
        file.download_file_slice(common.rand_str(), 1, 10)


def test_error_when_start_is_negative(mock_data_client):
    file = DataFile(mock_data_client, common.rand_str())
    with pytest.raises(ValueError):
        file.download_file_slice(common.rand_str(), -1, 1)


def test_error_when_end_is_negative(mock_data_client):
    file = DataFile(mock_data_client, common.rand_str())
    with pytest.raises(ValueError):
        file.download_file_slice(common.rand_str(), 0, -1)


def test_slice_file_name_removes_tmp_suffix_when_successful(mock_data_server, mock_data_client, slice_file):
    # Given: a file that exist in EGA object store and the user has permissions to access to it
    mock_data_server.file_content[slice_file.id] = slice_file.binary

    # When: the user successfully downloads a chunk
    file = DataFile(mock_data_client, slice_file.id)
    file.download_file_slice(slice_file.original_file_name, slice_file.start, slice_file.length)

    # Then: the suffix .tmp is removed from file for the successful chunk
    assert os.path.exists(slice_file.file_name)
    assert not os.path.exists(slice_file.file_name + '.tmp')


def test_chunk_fails_to_download(mock_data_server, mock_data_client, slice_file):
    # Given: a file that exist in EGA object store and the user has permissions to access to it
    mock_data_server.file_content[slice_file.id] = slice_file.binary

    slice_length = len(slice_file.binary) + 10

    # When: the user unsuccessfully downloads a chunk
    file_name = common.rand_str()
    file = DataFile(mock_data_client, slice_file.id)
    try:
        file.download_file_slice(file_name, slice_file.start, slice_length)
    except:
        # For the purpose of this test the download should fail
        pass

    # Then: file for the failed chunk is removed
    file_name_for_slice = file_name + '-from-' + str(slice_file.start) + '-len-' + str(slice_length) + '.slice'
    assert not os.path.exists(file_name_for_slice)
    assert not os.path.exists(file_name_for_slice + '.tmp')


def test_return_slice_file_when_existing(mock_data_server, mock_data_client, slice_file):
    # Given: a slice file existing in tmp directory
    mock_data_server.file_content[slice_file.id] = slice_file.binary
    file = DataFile(mock_data_client, slice_file.id)

    mock_stat = Mock()
    mock_stat.st_size = slice_file.length

    with patch.object(mock_data_client, 'get_stream', wraps=mock_data_client.get_stream) as get_stream_mock, \
            mock.patch("os.path.exists", lambda path: True if path == slice_file.file_name else False), \
            mock.patch("os.path.getsize", lambda path: slice_file.length), \
            mock.patch("os.stat", lambda path: mock_stat):
        # When: the slice file is downloaded
        filename = file.download_file_slice(slice_file.original_file_name, slice_file.start, slice_file.length)
        # Then: the existing slice file with same length is reused and data is not re-fetched
        assert filename == slice_file.file_name
        get_stream_mock.assert_not_called()


def test_remove_existing_slice_file_and_download_that_slice(mock_data_server, mock_data_client, slice_file):
    # Given: a slice.tmp file existing in tmp directory
    mock_data_server.file_content[slice_file.id] = slice_file.binary
    file = DataFile(mock_data_client, slice_file.id)

    m_open = mock.mock_open()
    mock_file_exists = {slice_file.file_name: False}
    slice_temp_file_name = slice_file.file_name + '.tmp'
    mock_file_exists[slice_temp_file_name] = True
    download_mock = SliceFileDownloadMock(slice_file)
    with mock.patch("builtins.open", m_open, create=True), \
            mock.patch("os.remove") as remove_file_mock, \
            mock.patch("os.path.exists", lambda path: mock_file_exists.get(path)), \
            mock.patch("os.path.getsize",
                       lambda path: download_mock.written_bytes if path == slice_temp_file_name else 0), \
            mock.patch("os.rename"):
        m_open().write.side_effect = download_mock.write
        # When: the slice file is downloaded
        output_file = file.download_file_slice(slice_file.original_file_name, slice_file.start, slice_file.length)
        # Then: delete the existing .slice.tmp file and download that slice
        assert slice_file.length == download_mock.written_bytes
        assert output_file == slice_file.file_name
        remove_file_mock.assert_called_once_with(slice_temp_file_name)
    m_open.assert_called_with(slice_temp_file_name, 'ba')


def teardown_module():
    for f in glob.glob(f'{os.getcwd()}/*.slice'):
        os.remove(f)


class SliceFileDownloadMock:
    def __init__(self, slice_file):
        self.written_bytes = 0
        self.slice_file = slice_file

    def write(self, buf):
        buf_len = len(buf)
        start = self.slice_file.start + self.written_bytes
        end = self.slice_file.start + self.written_bytes + buf_len
        expected_buf = self.slice_file.binary[start:end]
        assert expected_buf == buf
        self.written_bytes += buf_len
