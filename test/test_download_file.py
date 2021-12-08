import hashlib
import math
import os
import tempfile
from collections import namedtuple
from unittest import mock

import pytest

from pyega3.libs.data_file import DataFile

OUTPUT_DIR = tempfile.gettempdir()


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
        with mock.patch('os.makedirs', return_value=None):
            with mock.patch('os.path.exists', lambda path: os.path.basename(path) in files):
                with mock.patch('os.stat', os_stat_mock):
                    with mock.patch('os.rename', os_rename_mock):
                        with mock.patch('shutil.rmtree'):
                            with mock.patch('os.listdir', return_value=[]):
                                yield files


def test_download_file(mock_data_server, random_binary_file, mock_writing_files, mock_server_config, mock_data_client):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    file_md5 = hashlib.md5(random_binary_file).hexdigest()

    mock_data_server.file_content[file_id] = random_binary_file

    file = DataFile(mock_data_client, file_id, display_file_name=file_name, file_name=file_name + ".cip",
                    size=len(random_binary_file) + 16, unencrypted_checksum=file_md5)
    file.download_file_retry(1, output_dir=OUTPUT_DIR, genomic_range_args=None, max_retries=5, retry_wait=0)
    assert random_binary_file == mock_writing_files[file_name]


def test_no_error_if_output_file_already_exists_with_correct_md5(mock_data_server, random_binary_file,
                                                                 mock_writing_files, mock_server_config,
                                                                 mock_data_client):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    file_md5 = hashlib.md5(random_binary_file).hexdigest()

    mock_data_server.file_content[file_id] = random_binary_file

    mock_writing_files[file_name] = random_binary_file

    # add 16 bytes to file size ( IV adjustment )
    file = DataFile(mock_data_client, file_id, display_file_name=file_name, file_name=file_name + ".cip",
                    size=len(random_binary_file) + 16, unencrypted_checksum=file_md5)
    file.download_file_retry(1,
                             output_dir=OUTPUT_DIR,
                             genomic_range_args=None, max_retries=5, retry_wait=0)


def test_output_file_is_removed_if_md5_was_invalid(mock_data_server, random_binary_file, mock_writing_files,
                                                   mock_server_config,
                                                   mock_data_client):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    wrong_md5 = "wrong_md5_exactly_32_chars_longg"

    mock_data_server.file_content[file_id] = random_binary_file

    file = DataFile(mock_data_client, file_id, file_name, file_name + ".cip", len(random_binary_file) + 16, wrong_md5)

    with mock.patch('os.remove') as mocked_remove:
        with pytest.raises(Exception):
            file.download_file_retry(1, OUTPUT_DIR, genomic_range_args=None, max_retries=5, retry_wait=0)

    mocked_remove.assert_has_calls(
        [mock.call(os.path.join(os.getcwd(), file_id, os.path.basename(f))) for f in
         list(mock_writing_files.keys()) if file_name not in f],
        any_order=True)


def test_genomic_range_calls_htsget(mock_data_server, random_binary_file, mock_writing_files, mock_server_config,
                                    mock_data_client):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    file_md5 = hashlib.md5(random_binary_file).hexdigest()

    mock_data_server.file_content[file_id] = random_binary_file

    file = DataFile(mock_data_client, file_id, file_name, file_name + ".cip", len(random_binary_file) + 16, file_md5)

    with mock.patch('htsget.get') as mocked_htsget:
        file.download_file_retry(
            1, output_dir=OUTPUT_DIR, genomic_range_args=("chr1", None, 1, 100, None),
            max_retries=5,
            retry_wait=0)

    args, kwargs = mocked_htsget.call_args
    assert args[0] == f'{mock_server_config.url_api_ticket}/files/EGAF00000000001'

    assert kwargs.get('reference_name') == 'chr1'
    assert kwargs.get('reference_md5') is None
    assert kwargs.get('start') == 1
    assert kwargs.get('end') == 100
    assert kwargs.get('data_format') is None


def test_gpg_files_not_supported(mock_data_client):
    file = DataFile(mock_data_client, "", "test.gz", "test.gz.gpg", 0, "")

    file.download_file_retry(1, output_dir=OUTPUT_DIR, genomic_range_args=None, max_retries=5, retry_wait=5)


def test_temporary_chunk_files_stored_in_temp_folder_with_suffix_tmp(mock_data_server, random_binary_file,
                                                                     mock_server_config,
                                                                     mock_data_client):
    # Given: a file that exist in EGA object store and the user has permissions to access to it
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    file_md5 = hashlib.md5(random_binary_file).hexdigest()

    mock_data_server.file_content[file_id] = random_binary_file

    file = DataFile(mock_data_client, file_id, file_name, file_name + ".cip", len(random_binary_file) + 16, file_md5)

    # When: the user starts to download a file
    output_file = os.path.join(OUTPUT_DIR, file_id, file_name)
    md5_file = output_file + ".md5"
    if os.path.exists(output_file):
        os.remove(output_file)
    if os.path.exists(md5_file):
        os.remove(md5_file)

    with mock.patch('builtins.open', wraps=open) as wrapped_open:
        file.download_file_retry(1, output_dir=OUTPUT_DIR, genomic_range_args=None, max_retries=5, retry_wait=0)

    # Then: The temporary files for the chunks are in the temporary folder and has .tmp as a suffix
    temporary_folder = os.path.join(OUTPUT_DIR, file_id, ".tmp_download")
    # call[1] is a list of positional arguments which were passed to open():
    slices_opened = set([call[1][0] for call in wrapped_open.mock_calls if len(call[1]) == 2])
    slices_opened.remove(output_file)
    slices_opened.remove(md5_file)

    for slice_file in slices_opened:
        assert slice_file.startswith(temporary_folder)
        assert slice_file.endswith(".tmp")


# Feature: The user can configure the slice sizes used when downloading a file.

def test_the_user_specifies_a_slice_size(mock_data_client):
    # Given: a file that the user has permissions to download and a custom slice size
    file = DataFile(mock_data_client, file_id="EGAF123456", size=12345, unencrypted_checksum="testChecksum")
    slice_size = 1000

    # When: when the user downloads the file
    with mock.patch("pyega3.libs.data_file.DataFile.download_file_slice") as mock_download_slice:
        with mock.patch("pyega3.libs.utils.md5", return_value=file.unencrypted_checksum):
            with mock.patch("os.path.getsize", return_value=file.size):
                file.download_file(output_file="output_file", num_connections=1, max_slice_size=slice_size)

    # Then: the file is downloaded in multiple slices where each slice is at most the custom slice size
    assert mock_download_slice.call_count == 13


def test_the_user_does_not_specifies_a_slice_size(mock_data_client):
    # Given: a file that the user has permissions to download
    file = DataFile(mock_data_client, file_id="EGAF123456", size=1234567890, unencrypted_checksum="testChecksum")

    # When: when the user downloads the file
    with mock.patch("pyega3.libs.data_file.DataFile.download_file_slice") as mock_download_slice:
        with mock.patch("pyega3.libs.utils.md5", return_value=file.unencrypted_checksum):
            with mock.patch("os.path.getsize", return_value=file.size):
                file.download_file(output_file="output_file", num_connections=1)

    # Then: The file is downloaded in multiple slices where each slice is at most the default slice size
    assert mock_download_slice.call_count == math.ceil(file.size / DataFile.DEFAULT_SLICE_SIZE)


def test_the_user_specifies_a_custom_slice_size_different_to_before(mock_data_client, mock_data_server, random_binary_file, caplog):
    # Given: a file that the user has permissions to download and a custom slice size and some slices that were already downloaded with different size.
    mock_data_server.file_content["EGAF123456"] = random_binary_file
    file = DataFile(mock_data_client, file_id="EGAF123456", size=12345, unencrypted_checksum="testChecksum")
    slice_size = 1000
    os.makedirs(".tmp_download", exist_ok=True)

    extra_slice = file.download_file_slice(f'.tmp_download/{file.id}', 0, 1234)
    assert os.path.exists(extra_slice)

    # When: when the user downloads the file
    with mock.patch("pyega3.libs.data_file.DataFile.download_file_slice") as mock_download_slice:
        with mock.patch("pyega3.libs.utils.md5", return_value=file.unencrypted_checksum):
            with mock.patch("os.path.getsize", return_value=file.size):
                file.download_file(output_file="output_file", num_connections=1, max_slice_size=slice_size)

    # Then: the file is downloaded in multiple slices where each slice is at most the custom slice size and delete the old slices with the warning.
    assert mock_download_slice.call_count == 13
    assert not os.path.exists(extra_slice)
    assert "Deleting the leftover" in caplog.text

