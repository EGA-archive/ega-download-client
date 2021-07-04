import os

import responses

from pyega3 import pyega3 as pyega3


def test_failed_download_retries_from_where_it_stopped(temporary_output_file, mock_requests, mock_server_config,
                                                       mock_auth_client):
    """
    It was not possible to download the whole file on the first download attempt,
    so the script retries for a second time and continues from where it stopped
    on the first attempt.
    """

    file_id = 'test_file_id_1'
    file_size_without_iv = 92700
    file_size_with_iv = file_size_without_iv + 16

    amount_of_missing_bytes = 123
    file_size_with_missing_bytes = file_size_without_iv - amount_of_missing_bytes

    input_file_with_few_bytes_missing = bytearray(os.urandom(file_size_with_missing_bytes))
    rest_of_the_input_file = bytearray(os.urandom(amount_of_missing_bytes))

    mock_requests.add(responses.GET, f'{mock_server_config.url_api}/files/{file_id}',
                      body=input_file_with_few_bytes_missing,
                      status=200)
    mock_requests.add(responses.GET, f'{mock_server_config.url_api}/files/{file_id}', body=rest_of_the_input_file,
                      status=200)

    pyega3.download_file_retry(mock_auth_client, file_id, temporary_output_file, temporary_output_file,
                               file_size_with_iv, 'check_sum', 1, temporary_output_file, None, 2, 0.1,
                               mock_server_config, key=None)

    assert mock_requests.calls[0].request.headers.get('Range') == 'bytes=0-92699'
    assert mock_requests.calls[1].request.headers.get('Range') == 'bytes=92577-92699'
    assert mock_requests.calls[1].request.headers.get('Range') == 'bytes={}-92699'.format(file_size_with_missing_bytes)

    assert os.path.exists(temporary_output_file)
    output_file_size = os.stat(temporary_output_file).st_size
    assert output_file_size == file_size_without_iv
    os.remove(temporary_output_file)
