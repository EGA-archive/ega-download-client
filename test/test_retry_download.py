import os

import responses

from pyega3 import pyega3 as pyega3


def test_failed_download_retries_from_where_it_stopped(temporary_output_file, mock_requests):
    """
    It was not possible to download the whole file on the first download attempt,
    so the script retries for a second time and continues from where it stopped
    on the first attempt.
    """

    pyega3.URL_AUTH = 'https://test.auth.server/ega-openid-connect-server/token'
    pyega3.URL_API = 'https://test.data.server'
    pyega3.URL_API_TICKET = 'https://test.ticket.server',
    pyega3.CLIENT_SECRET = 'test-client-secret'

    file_id = 'test_file_id_1'
    file_size_without_iv = 92700
    file_size_with_iv = file_size_without_iv + 16

    mock_requests.add(responses.POST, pyega3.URL_AUTH, json={'access_token': 'ok'}, status=200)

    amount_of_missing_bytes = 123
    file_size_with_missing_bytes = file_size_without_iv - amount_of_missing_bytes

    input_file_with_few_bytes_missing = bytearray(os.urandom(file_size_with_missing_bytes))
    rest_of_the_input_file = bytearray(os.urandom(amount_of_missing_bytes))

    mock_requests.add(responses.GET, f'{pyega3.URL_API}/files/{file_id}', body=input_file_with_few_bytes_missing,
                      status=200)
    mock_requests.add(responses.GET, f'{pyega3.URL_API}/files/{file_id}', body=rest_of_the_input_file, status=200)

    pyega3.download_file_retry(('', ''), file_id, temporary_output_file, temporary_output_file,
                               file_size_with_iv, 'check_sum', 1, None, temporary_output_file, None, 2, 0.1)

    assert mock_requests.calls[1].request.headers.get('Range') == 'bytes=0-92699'
    assert mock_requests.calls[2].request.headers.get('Range') == 'bytes=92577-92699'
    assert mock_requests.calls[2].request.headers.get('Range') == 'bytes={}-92699'.format(file_size_with_missing_bytes)

    assert os.path.exists(temporary_output_file)
    output_file_size = os.stat(temporary_output_file).st_size
    assert output_file_size == file_size_without_iv
    os.remove(temporary_output_file)
