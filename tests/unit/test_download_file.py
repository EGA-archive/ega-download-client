import hashlib
import math
import os
import tempfile
import threading
from collections import namedtuple
from datetime import datetime
from typing import List
from unittest import mock

import pytest
import requests

from pyega3.libs.data_file import DataFile, _make_slice_progress_guard
from pyega3.libs.error import AuthenticationError, MaxRetriesReachedError, MD5MismatchError, SliceError
from pyega3.libs.stats import Stats

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
        X = namedtuple('X', 'st_size st_mtime f1 f2 f3 f4 f5 f6 f7 f8 f9')
        result = X(*([None] * 11))
        return result._replace(st_size=len(files.get(fn, "")))

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
    correct_md5 = hashlib.md5(random_binary_file).hexdigest()
    file = _create_data_file_with_md5(mock_data_client, mock_data_server, random_binary_file, correct_md5)
    file.download_file_retry(1, output_dir=OUTPUT_DIR, genomic_range_args=None, max_retries=5, retry_wait=0)
    assert random_binary_file == mock_writing_files[file.display_name]


def test_no_error_if_output_file_already_exists_with_correct_md5(mock_data_server, random_binary_file,
                                                                 mock_writing_files, mock_server_config,
                                                                 mock_data_client):
    correct_file_md5 = hashlib.md5(random_binary_file).hexdigest()
    file = _create_data_file_with_md5(mock_data_client, mock_data_server, random_binary_file, correct_file_md5)
    mock_writing_files[file.display_name] = random_binary_file
    file.download_file_retry(1,
                             output_dir=OUTPUT_DIR,
                             genomic_range_args=None, max_retries=5, retry_wait=0)


def test_output_file_is_removed_if_md5_was_invalid(mock_data_server, random_binary_file, mock_writing_files,
                                                   mock_server_config,
                                                   mock_data_client):
    wrong_md5 = "wrong_md5_exactly_32_chars_longg"
    file = _create_data_file_with_md5(mock_data_client, mock_data_server, random_binary_file, wrong_md5)

    with mock.patch('os.remove') as mocked_remove:
        with pytest.raises(Exception):
            file.download_file_retry(1, OUTPUT_DIR, genomic_range_args=None, max_retries=5, retry_wait=0)

    mocked_remove.assert_has_calls(
        [mock.call(os.path.join(os.getcwd(), file.id, os.path.basename(f))) for f in
         list(mock_writing_files.keys()) if file.display_name not in f],
        any_order=True)


def test_post_stats_if_download_succeeded(mock_data_server, random_binary_file, mock_writing_files,
                                          mock_server_config, mock_data_client):
    correct_file_md5 = hashlib.md5(random_binary_file).hexdigest()
    file = _create_data_file_with_md5(mock_data_client, mock_data_server, random_binary_file, correct_file_md5)
    stats = file.download_file_retry(1, output_dir=OUTPUT_DIR, genomic_range_args=None, max_retries=5, retry_wait=0)
    assert len(stats) == 1
    assert stats[0].status == "Succeeded"
    assert stats[0].session_id == "sessionid"
    assert stats[0].user_id == "EGAW123"
    assert stats[0].file_size_in_bytes == file.size
    assert stats[0].error_reason is None
    assert stats[0].error_details is None
    assert stats[0].number_of_connections == 1
    assert stats[0].number_of_attempts == 1
    assert stats[0].client_stats_created_at > stats[0].client_download_started_at


def test_telemetry_failure_does_not_change_download_success(mock_data_server, random_binary_file,
                                                            mock_writing_files, mock_data_client):
    correct_md5 = hashlib.md5(random_binary_file).hexdigest()
    file = _create_data_file_with_md5(mock_data_client, mock_data_server, random_binary_file, correct_md5)

    with mock.patch.object(mock_data_client, "post_stats", side_effect=RuntimeError("telemetry failed")) as post_stats:
        stats = file.download_file_retry(1, output_dir=OUTPUT_DIR, genomic_range_args=None,
                                         max_retries=5, retry_wait=0)

    assert post_stats.call_count == 1
    assert len(stats) == 1
    assert stats[0].status == "Succeeded"


def test_telemetry_network_failure_is_not_retried(mock_data_client):
    now = datetime.now()
    stats = Stats.succeeded(now, now, "EGAF123456", 1, 100, 1)

    with mock.patch.object(
            mock_data_client.session, "post", side_effect=requests.exceptions.ConnectTimeout("telemetry timeout")
    ) as post:
        assert mock_data_client.post_stats(stats) is None

    assert post.call_count == 1


def test_post_no_stats_if_file_exists_with_correct_md5(mock_data_server, random_binary_file,
                                                       mock_writing_files, mock_server_config,
                                                       mock_data_client):
    file_md5 = hashlib.md5(random_binary_file).hexdigest()
    file = _create_data_file_with_md5(mock_data_client, mock_data_server, random_binary_file, file_md5)
    mock_writing_files[file.display_name] = random_binary_file
    stats = file.download_file_retry(1,
                                     output_dir=OUTPUT_DIR,
                                     genomic_range_args=None, max_retries=5, retry_wait=0)
    assert len(stats) == 0


def test_post_stats_if_download_failed(mock_data_server, random_binary_file, mock_writing_files,
                                       mock_server_config,
                                       mock_data_client):
    wrong_md5 = "wrong_md5_exactly_32_chars_longg"
    file = _create_data_file_with_md5(mock_data_client, mock_data_server, random_binary_file, wrong_md5)
    with mock.patch('os.remove'):
        with pytest.raises(MaxRetriesReachedError) as exception_info:
            file.download_file_retry(1, OUTPUT_DIR, genomic_range_args=None, max_retries=5, retry_wait=0)

    final_exception = exception_info.value
    cause = final_exception.__cause__
    assert exception_info.type == MaxRetriesReachedError
    assert isinstance(cause, MD5MismatchError)
    stats: List[Stats] = exception_info.value.download_stats_list
    assert len(stats) == 1
    assert stats[0].session_id == "sessionid"
    assert stats[0].user_id == "EGAW123"
    assert stats[0].status == "Failed"
    assert stats[0].error_details == cause.message
    assert stats[0].error_reason == cause.__class__.__name__


def _create_data_file_with_md5(mock_data_client, mock_data_server, random_binary_file, file_md5):
    file_id = "EGAF00000000001"
    file_name = "resulting.file"
    mock_data_server.file_content[file_id] = random_binary_file
    file = DataFile(mock_data_client, file_id, file_name, file_name + ".cip", len(random_binary_file) + 16, file_md5)
    return file


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

def _download_with_mocked_slices(file, mock_download_slice, **kwargs):
    mock_download_slice.side_effect = lambda *args: args[2]

    def get_size(path):
        return path if isinstance(path, int) else file.size - 16

    with mock.patch("pyega3.libs.utils.merge_bin_files_on_disk", return_value=file.unencrypted_checksum), \
            mock.patch("os.path.getsize", side_effect=get_size):
        file.download_file(**kwargs)


def test_the_user_specifies_a_slice_size(mock_data_client):
    # Given: a file that the user has permissions to download and a custom slice size
    file = DataFile(mock_data_client, file_id="EGAF123456", size=12345, unencrypted_checksum="testChecksum")
    slice_size = 1000

    # When: when the user downloads the file
    with mock.patch("pyega3.libs.data_file.DataFile.download_file_slice") as mock_download_slice:
        _download_with_mocked_slices(
            file, mock_download_slice,
            output_file="output_file", num_connections=1, max_slice_size=slice_size
        )

    # Then: the file is downloaded in multiple slices where each slice is at most the custom slice size
    assert mock_download_slice.call_count == 13


def test_the_user_does_not_specifies_a_slice_size(mock_data_client):
    # Given: a file that the user has permissions to download
    file = DataFile(mock_data_client, file_id="EGAF123456", size=1234567890, unencrypted_checksum="testChecksum")

    # When: when the user downloads the file
    with mock.patch("pyega3.libs.data_file.DataFile.download_file_slice") as mock_download_slice:
        _download_with_mocked_slices(
            file, mock_download_slice, output_file="output_file", num_connections=1
        )

    # Then: The file is downloaded in multiple slices where each slice is at most the default slice size
    assert mock_download_slice.call_count == math.ceil(file.size / DataFile.DEFAULT_SLICE_SIZE)


def test_the_user_specifies_a_custom_slice_size_different_to_before(mock_data_client, mock_data_server,
                                                                    random_binary_file, caplog):
    # Given: a file that the user has permissions to download and a custom slice size and some slices that were already downloaded with different size.
    mock_data_server.file_content["EGAF123456"] = random_binary_file
    file = DataFile(mock_data_client, file_id="EGAF123456", size=12345, unencrypted_checksum="testChecksum")
    slice_size = 1000
    os.makedirs(".tmp_download", exist_ok=True)

    extra_slice = file.download_file_slice(f'.tmp_download/{file.id}', 0, 1234)
    assert os.path.exists(extra_slice)

    # When: when the user downloads the file
    with mock.patch("pyega3.libs.data_file.DataFile.download_file_slice") as mock_download_slice:
        _download_with_mocked_slices(
            file, mock_download_slice,
            output_file="output_file", num_connections=1, max_slice_size=slice_size
        )

    # Then: the file is downloaded in multiple slices where each slice is at most the custom slice size and delete the old slices with the warning.
    assert mock_download_slice.call_count == 13
    assert not os.path.exists(extra_slice)
    assert "Deleting the leftover" in caplog.text


def test_slice_file_is_reused(mock_data_client, mock_data_server, random_binary_file, caplog):
    # Given: a file that the user has permissions to
    # download and a custom slice size and some slices that
    # were already downloaded with correct size.
    mock_data_server.file_content["EGAF123456"] = random_binary_file
    file = DataFile(mock_data_client, file_id="EGAF123456", size=12345, unencrypted_checksum="testChecksum")
    slice_size = 1000
    os.makedirs(".tmp_download", exist_ok=True)

    extra_slice = file.download_file_slice(f'.tmp_download/{file.id}', 0, slice_size)
    assert os.path.exists(extra_slice)

    # When: when the user downloads the file
    with mock.patch("pyega3.libs.data_file.DataFile.download_file_slice") as mock_download_slice:
        _download_with_mocked_slices(
            file, mock_download_slice,
            output_file="output_file", num_connections=1, max_slice_size=slice_size
        )

    # Then: the file is downloaded in multiple
    # slices where each slice is at most the custom
    # slice size and old slices is not deleted.
    assert mock_download_slice.call_count == 13
    assert os.path.exists(extra_slice)
    assert "Deleting the leftover" not in caplog.text


def test_wrong_sized_cached_slice_is_redownloaded(mock_data_client, mock_data_server, tmp_path):
    file_id = "EGAF123456"
    content = b"replacement slice content"
    mock_data_server.file_content[file_id] = content
    file = DataFile(mock_data_client, file_id, size=len(content) + 16, unencrypted_checksum="testChecksum")
    slice_base = str(tmp_path / file_id)
    cached_slice = f"{slice_base}-from-0-len-{len(content)}.slice"

    with open(cached_slice, "wb") as cached:
        cached.write(b"incomplete")

    result = file.download_file_slice(slice_base, 0, len(content))

    assert result == cached_slice
    with open(result, "rb") as downloaded:
        assert downloaded.read() == content


def test_slice_failure_is_requeued_without_collapsing_other_work(mock_data_client):
    file = DataFile(mock_data_client, file_id="EGAF123456", size=100, unencrypted_checksum="testChecksum")
    params = [("slice", start, 10, None, None) for start in (0, 10, 20)]
    attempts = {0: 0, 10: 0, 20: 0}

    def download_slice(param):
        start = param[1]
        attempts[start] += 1
        if start == 10 and attempts[start] == 1:
            raise requests.exceptions.ConnectionError("transient failure")
        return f"slice-{start}"

    with mock.patch.object(file, "download_file_slice_", side_effect=download_slice):
        results = file._download_file_slices(params, num_workers=2)

    assert results == ["slice-0", "slice-10", "slice-20"]
    assert attempts == {0: 1, 10: 2, 20: 1}


def test_worker_count_is_limited_by_slice_count(mock_data_client):
    file = DataFile(mock_data_client, file_id="EGAF123456", size=100, unencrypted_checksum="testChecksum")
    params = [("slice", start, 10, None, None) for start in (0, 10)]
    real_thread = threading.Thread
    workers = []

    def record_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        workers.append(thread)
        return thread

    with mock.patch.object(file, "download_file_slice_", side_effect=lambda param: f"slice-{param[1]}"), \
            mock.patch("pyega3.libs.data_file.threading.Thread", side_effect=record_thread):
        assert file._download_file_slices(params, num_workers=30) == ["slice-0", "slice-10"]

    assert len(workers) == len(params)


def test_slice_retries_are_bounded(mock_data_client):
    file = DataFile(mock_data_client, file_id="EGAF123456", size=100, unencrypted_checksum="testChecksum")
    params = [("slice", 0, 10, None, None)]
    attempts = 0

    def download_slice(param):
        nonlocal attempts
        attempts += 1
        raise requests.exceptions.ConnectionError("persistent failure")

    with mock.patch.object(file, "download_file_slice_", side_effect=download_slice):
        with pytest.raises(requests.exceptions.ConnectionError):
            file._download_file_slices(params, num_workers=1)

    assert attempts == 3


def test_exhausted_slice_failure_cancels_pending_work(mock_data_client):
    file = DataFile(mock_data_client, file_id="EGAF123456", size=100, unencrypted_checksum="testChecksum")
    params = [("slice", start, 10, None, None) for start in (0, 10, 20)]
    attempted_starts = []

    def download_slice(param):
        attempted_starts.append(param[1])
        raise requests.exceptions.ConnectionError("persistent failure")

    with mock.patch.object(file, "download_file_slice_", side_effect=download_slice):
        with pytest.raises(requests.exceptions.ConnectionError):
            file._download_file_slices(params, num_workers=1)

    assert attempted_starts == [0, 10, 20, 0, 10, 20, 0]


def test_exhausted_server_retry_is_not_requeued(mock_data_client):
    file = DataFile(mock_data_client, file_id="EGAF123456", size=100, unencrypted_checksum="testChecksum")
    params = [("slice", start, 10, None, None) for start in (0, 10, 20)]

    with mock.patch.object(
            file, "download_file_slice_", side_effect=requests.exceptions.RetryError("cooldown exhausted")) as worker:
        with pytest.raises(requests.exceptions.RetryError):
            file._download_file_slices(params, num_workers=1)

    assert worker.call_count == 1


def test_worker_authentication_failure_cancels_remaining_slices(mock_data_client):
    file = DataFile(mock_data_client, file_id="EGAF123456", size=100, unencrypted_checksum="testChecksum")
    params = [("slice", start, 10, None, None) for start in (0, 10, 20)]
    attempted_starts = []

    def download_slice(param):
        attempted_starts.append(param[1])
        raise AuthenticationError("authentication failed")

    with mock.patch.object(file, "download_file_slice_", side_effect=download_slice):
        with pytest.raises(AuthenticationError):
            file._download_file_slices(params, num_workers=1)

    assert attempted_starts == [0]


def test_worker_authentication_failure_uses_file_failure_lifecycle(mock_data_client):
    file = DataFile(mock_data_client, "EGAF123456", "result", "result.cip", 100, "checksum")
    params = [("slice", start, 10, None, None) for start in (0, 10, 20)]

    def download_with_workers(*_args):
        file._download_file_slices(params, num_workers=1)

    delete_temporaries = DataFile.temporary_files_should_be_deleted
    DataFile.temporary_files_should_be_deleted = True
    try:
        with mock.patch.object(file, "does_file_exist", return_value=False), \
                mock.patch.object(file, "_check_and_warn_if_file_is_bigger_than_free_space"), \
                mock.patch.object(file, "_create_temp_dir", return_value=".tmp_download"), \
                mock.patch.object(file, "download_file", side_effect=download_with_workers), \
                mock.patch.object(file, "download_file_slice_", side_effect=AuthenticationError("expired token")) as worker, \
                mock.patch.object(file, "delete_temporary_folder") as cleanup, \
                mock.patch.object(mock_data_client, "post_stats") as post_stats:
            with pytest.raises(AuthenticationError, match="expired token"):
                file.download_file_retry(1, OUTPUT_DIR, None, max_retries=5, retry_wait=0)
    finally:
        DataFile.temporary_files_should_be_deleted = delete_temporaries

    assert worker.call_count == 1
    cleanup.assert_called_once_with(".tmp_download")
    assert post_stats.call_count == 1
    assert post_stats.call_args[0][0].status == "Failed"


def test_slice_progress_guard_rejects_sustained_pathological_slowdown():
    with mock.patch(
        "pyega3.libs.data_file.time.monotonic",
        side_effect=[0, 15, 60, 106],
    ):
        guard = _make_slice_progress_guard(lambda: 1_000_000)
        guard(1_000)
        guard(2_000)
        with pytest.raises(SliceError, match="pathologically slow"):
            guard(3_000)


def test_slice_progress_guard_is_relative_to_download_baseline():
    with mock.patch(
        "pyega3.libs.data_file.time.monotonic",
        side_effect=[0, 30, 75, 121],
    ):
        guard = _make_slice_progress_guard(lambda: 100_000)
        guard(1_500_000)
        guard(3_750_000)
        guard(6_050_000)


def teardown_module():
    filepath = 'output_file.md5'
    if os.path.exists(filepath):
        os.remove(filepath)
