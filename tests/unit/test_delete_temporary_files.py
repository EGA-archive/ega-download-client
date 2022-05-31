import os
import re

import pytest
import responses

from pyega3.libs.data_file import DOWNLOAD_FILE_MEMORY_BUFFER_SIZE, DataFile

test_file_id = 'test_file_id1'
expected_file_size = DOWNLOAD_FILE_MEMORY_BUFFER_SIZE * 3


def test_temp_files_are_deleted_automatically_if_there_are_no_exceptions(mock_server_config,
                                                                         mock_auth_client,
                                                                         temporary_output_file,
                                                                         mock_requests,
                                                                         mock_data_client):
    """
    The temporary files are deleted by the algorithm automatically, during the happy path,
    when the temporary files are assembled into the final, big file.
    There's no need for extra deleting-mechanism.
    """
    DataFile.temporary_files_should_be_deleted = False

    file_size_without_iv = 92700
    file_size_with_iv = file_size_without_iv + 16

    input_file = bytearray(os.urandom(file_size_without_iv))
    mock_requests.add(responses.GET, f'{mock_server_config.url_api}/files/{test_file_id}', body=input_file, status=200)

    file = DataFile(mock_data_client, test_file_id, temporary_output_file, temporary_output_file, file_size_with_iv,
                    'check_sum')

    output_dir = os.path.dirname(temporary_output_file)
    file.download_file_retry(1, output_dir, None, 2, 0.1)

    temp_file = file.temporary_files.pop()
    # The temporary file should not exist because everything went fine,
    # and it was deleted automatically:
    assert not os.path.exists(temp_file)

    display_file_name = os.path.basename(temporary_output_file)
    downloaded_file = f'{output_dir}/{test_file_id}/{display_file_name}'
    assert os.path.exists(downloaded_file)
    output_file_size = os.stat(downloaded_file).st_size
    assert output_file_size == file_size_without_iv
    os.remove(downloaded_file)


def download_with_exception(mock_requests, output_file_path, mock_server_config, file):
    """
    Simulates downloading a file of the given size: "true_file_size".
    During the transfer, an exception happens and the temporary file is either deleted
    or kept, depending on the TEMPORARY_FILES_SHOULD_BE_DELETED flag.
    """

    number_of_retries = 2
    not_enough_bytes = int(expected_file_size / 3 - 1000)
    content = bytearray(os.urandom(not_enough_bytes))
    output_dir = os.path.dirname(output_file_path)

    # First, normal GET request:
    mock_requests.add(responses.GET, f'{mock_server_config.url_api}/files/{file.id}', body=content, status=200)
    # Then all the retry attempt:
    for _ in range(number_of_retries):
        mock_requests.add(responses.GET, f'{mock_server_config.url_api}/files/{file.id}', body=content, status=200)

    with pytest.raises(Exception) as context_manager:
        file.download_file_retry(1, output_dir, None, number_of_retries, 0.1)

    exception_message = str(context_manager.value)
    assert re.compile(r'Slice error: received=\d+, requested=\d+').search(exception_message)

    display_file_name = os.path.basename(output_file_path)
    downloaded_file = f'{output_dir}/{test_file_id}/{display_file_name}'
    assert not os.path.exists(downloaded_file)


def test_temporary_folder_is_deleted_if_the_user_says_so(mock_server_config,
                                                         mock_data_client,
                                                         temporary_output_file,
                                                         mock_requests):
    # Given: a file that exist in EGA object store and the user has permissions to access to it
    DataFile.temporary_files_should_be_deleted = True

    file = DataFile(mock_data_client, test_file_id, temporary_output_file, temporary_output_file, expected_file_size,
                    'check_sum')

    temporary_folder_name = os.path.join(os.path.dirname(temporary_output_file), test_file_id, '.tmp_download')

    # When: the user completes downloading a file
    download_with_exception(mock_requests, temporary_output_file, mock_server_config, file)

    # Then: the temporary folder and the temporary files are deleted
    assert not os.path.exists(temporary_folder_name)


def test_temporary_folder_is_not_deleted_if_the_user_says_so(mock_server_config,
                                                             mock_data_client,
                                                             temporary_output_file,
                                                             mock_requests):

    # Given: a file that exist in EGA object store and the user has permissions to access to it
    DataFile.temporary_files_should_be_deleted = False

    file = DataFile(mock_data_client, test_file_id, temporary_output_file, temporary_output_file, expected_file_size,
                    'check_sum')

    temporary_folder_name = os.path.join(os.path.dirname(temporary_output_file), test_file_id, '.tmp_download')

    # When: he user completes downloading a file
    download_with_exception(mock_requests, temporary_output_file, mock_server_config, file)

    # Then: the temporary folder and the temporary files are NOT deleted
    assert os.path.exists(temporary_folder_name)
