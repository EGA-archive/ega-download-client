import hashlib
import os
from collections import namedtuple
from unittest import mock

import pytest

import pyega3.pyega3 as pyega3


@pytest.fixture
def mock_writing_files():
    files = {}

    def open_wrapper(filename, mode):
        filename = os.path.basename(filename)
        if filename not in files:
            if 'r' in mode:
                raise Exception("Attempt to read mock file before it was created.")
            files[filename] = bytearray()
        content = bytes(files[filename])
        content_len = len(content)
        read_buf_sz = 65536
        file_object = mock.mock_open(read_data=content).return_value
        file_object.__iter__.return_value = [content[i:min(i + read_buf_sz, content_len)] for i in
                                             range(0, content_len, read_buf_sz)]
        file_object.write.side_effect = lambda write_buf: files[filename].extend(write_buf)
        return file_object

    def os_stat_mock(fn):
        fn = os.path.basename(fn)
        X = namedtuple('X', 'st_size f1 f2 f3 f4 f5 f6 f7 f8 f9')
        result = X(*([None] * 10))
        return result._replace(st_size=len(files[fn]))

    def os_rename_mock(s, d):
        files.__setitem__(os.path.basename(d), files.pop(os.path.basename(s)))

    with mock.patch('builtins.open', new=open_wrapper):
        with mock.patch('os.makedirs', lambda _: None):
            with mock.patch('os.path.exists', lambda path: os.path.basename(path) in files):
                with mock.patch('os.stat', os_stat_mock):
                    with mock.patch('os.rename', os_rename_mock):
                        yield files


def test_download_file(mock_data_server, random_binary_file, mock_writing_files):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    file_md5 = hashlib.md5(random_binary_file).hexdigest()

    mock_data_server.file_content[file_id] = random_binary_file

    with mock.patch("pyega3.pyega3.get_token", return_value=mock_data_server.token):
        pyega3.download_file_retry(
            # add 16 bytes to file size ( IV adjustment )
            None, file_id, file_name, file_name + ".cip", len(random_binary_file) + 16,
            file_md5, 1, None,
            output_file=None, genomic_range_args=None, max_retries=5, retry_wait=0)
        assert random_binary_file == mock_writing_files[file_name]


def test_no_error_if_output_file_already_exists_with_correct_md5(mock_data_server, random_binary_file,
                                                                 mock_writing_files):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    file_md5 = hashlib.md5(random_binary_file).hexdigest()

    mock_data_server.file_content[file_id] = random_binary_file

    mock_writing_files[file_name] = random_binary_file

    with mock.patch("pyega3.pyega3.get_token", return_value=mock_data_server.token):
        # add 16 bytes to file size ( IV adjustment )
        pyega3.download_file_retry(
            None, file_id, file_name, file_name + ".cip", len(random_binary_file) + 16,
            file_md5, 1, None,
            output_file=None, genomic_range_args=None, max_retries=5, retry_wait=0)


def test_output_file_is_removed_if_md5_was_invalid(mock_data_server, random_binary_file, mock_writing_files):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    wrong_md5 = "wrong_md5_exactly_32_chars_longg"

    mock_data_server.file_content[file_id] = random_binary_file

    with mock.patch("pyega3.pyega3.get_token", return_value=mock_data_server.token):
        with mock.patch('os.remove') as mocked_remove:
            with pytest.raises(Exception):
                pyega3.download_file_retry(
                    None, file_id, file_name, file_name + ".cip", len(random_binary_file) + 16,
                    wrong_md5, 1,
                    None, output_file=None, genomic_range_args=None, max_retries=5, retry_wait=0)

        mocked_remove.assert_has_calls(
            [mock.call(os.path.join(os.getcwd(), file_id, os.path.basename(f))) for f in
             list(mock_writing_files.keys()) if file_name not in f],
            any_order=True)


def test_genomic_range_calls_htsget(mock_data_server, random_binary_file, mock_writing_files):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    file_md5 = hashlib.md5(random_binary_file).hexdigest()

    mock_data_server.file_content[file_id] = random_binary_file

    pyega3.URL_API_TICKET = 'https://ega.ebi.ac.uk:8052/elixir/tickets/tickets'

    with mock.patch('htsget.get') as mocked_htsget:
        with mock.patch("pyega3.pyega3.get_token", return_value=mock_data_server.token):
            pyega3.download_file_retry(
                None, file_id, file_name, file_name + ".cip", len(random_binary_file) + 16,
                file_md5, 1, None,
                output_file=None, genomic_range_args=("chr1", None, 1, 100, None),
                max_retries=5,
                retry_wait=0)

    args, kwargs = mocked_htsget.call_args
    assert args[0] == 'https://ega.ebi.ac.uk:8052/elixir/tickets/tickets/files/EGAF00000000001'

    assert kwargs.get('reference_name') == 'chr1'
    assert kwargs.get('reference_md5') is None
    assert kwargs.get('start') == 1
    assert kwargs.get('end') == 100
    assert kwargs.get('data_format') is None


def test_encrypted_files_not_supported():
    with mock.patch("pyega3.pyega3.get_token", return_value="ok"):
        with pytest.raises(ValueError):
            pyega3.download_file_retry("", "", "", "", 0, 0, 1, "key", output_file=None, genomic_range_args=None,
                                       max_retries=5, retry_wait=0)


def test_gpg_files_not_supported():
    with mock.patch("pyega3.pyega3.get_token", return_value="ok"):
        pyega3.download_file_retry("", "", "test.gz", "test.gz.gpg", 0, 0, 1, None, output_file=None,
                                   genomic_range_args=None, max_retries=5, retry_wait=5)