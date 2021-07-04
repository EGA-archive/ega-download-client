import os
import re

import pytest
import responses

from pyega3 import pyega3 as pyega3

test_file_id = 'test_file_id1'
expected_file_size = pyega3.DOWNLOAD_FILE_SLICE_CHUNK_SIZE * 3


@pytest.fixture
def dummy_server_config():
    pyega3.URL_AUTH = 'https://test.auth.server/ega-openid-connect-server/token'
    pyega3.URL_API = 'https://test.data.server'
    pyega3.URL_API_TICKET = 'https://test.ticket.server',
    pyega3.CLIENT_SECRET = 'test-client-secret'


@pytest.fixture
def user_has_authenticated_successfully(mock_requests, dummy_server_config):
    mock_requests.add(responses.POST, pyega3.URL_AUTH, json={'access_token': 'ok'}, status=200)


def test_deleting_non_existent_file_does_not_raise_exception():
    non_existent_file = '/tmp/non/existent/file'
    assert not os.path.exists(non_existent_file)

    # No exception is raised:
    pyega3.delete_temporary_files([non_existent_file])


def test_temp_files_are_deleted_automatically_if_there_are_no_exceptions(dummy_server_config,
                                                                         user_has_authenticated_successfully,
                                                                         temporary_output_file,
                                                                         mock_requests):
    """
    The temporary files are deleted by the algorithm automatically, during the happy path,
    when the temporary files are assembled into the final, big file.
    There's no need for extra deleting-mechanism.
    """
    pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = False

    file_size_without_iv = 92700
    file_size_with_iv = file_size_without_iv + 16

    input_file = bytearray(os.urandom(file_size_without_iv))
    mock_requests.add(responses.GET, f'{pyega3.URL_API}/files/{test_file_id}', body=input_file, status=200)

    pyega3.download_file_retry(('', ''), test_file_id, temporary_output_file, temporary_output_file,
                               file_size_with_iv, 'check_sum', 1, None, temporary_output_file, None, 2, 0.1)

    temp_file = pyega3.TEMPORARY_FILES.pop()
    # The temporary file should not exist because everything went fine,
    # and it was deleted automatically:
    assert not os.path.exists(temp_file)

    assert os.path.exists(temporary_output_file)
    output_file_size = os.stat(temporary_output_file).st_size
    assert output_file_size == file_size_without_iv
    os.remove(temporary_output_file)


def download_with_exception(mock_requests, output_file_path):
    """
    Simulates downloading a file of the given size: "true_file_size".
    During the transfer, an exception happens and the temporary file is either deleted
    or kept, depending on the TEMPORARY_FILES_SHOULD_BE_DELETED flag.
    """

    number_of_retries = 2
    not_enough_bytes = int(expected_file_size / 3 - 1000)
    content = bytearray(os.urandom(not_enough_bytes))

    # First, normal GET request:
    mock_requests.add(responses.GET, f'{pyega3.URL_API}/files/{test_file_id}', body=content, status=200)
    # Then all the retry attempt:
    for _ in range(number_of_retries):
        mock_requests.add(responses.GET, f'{pyega3.URL_API}/files/{test_file_id}', body=content, status=200)

    with pytest.raises(Exception) as context_manager:
        pyega3.download_file_retry(('', ''), test_file_id, output_file_path, output_file_path,
                                   expected_file_size, 'check_sum', 1, None, output_file_path, None,
                                   number_of_retries, 0.1)

    exception_message = str(context_manager.value)
    assert re.compile(r'Slice error: received=\d+, requested=\d+').search(exception_message)

    assert not os.path.exists(output_file_path)


def test_temporary_files_are_deleted_if_the_user_says_so(dummy_server_config,
                                                         user_has_authenticated_successfully,
                                                         temporary_output_file,
                                                         mock_requests):
    pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = True

    download_with_exception(mock_requests, temporary_output_file)

    # The temporary file should not exist because the pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED
    # variable was set to True previously:
    assert not os.path.exists(pyega3.TEMPORARY_FILES.pop())


def test_temporary_files_are_not_deleted_if_the_user_says_so(dummy_server_config,
                                                             user_has_authenticated_successfully,
                                                             temporary_output_file,
                                                             mock_requests):
    # The user asks for keeping the temporary files:
    pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = False

    download_with_exception(mock_requests, temporary_output_file)

    temp_file = pyega3.TEMPORARY_FILES.pop()

    # The temporary file should exist because the pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED
    # variable was set to False previously:
    assert os.path.exists(temp_file)

    # The download client should have been able to download the whole file:
    assert os.stat(temp_file).st_size == expected_file_size - 3 * 1000

    os.remove(temp_file)