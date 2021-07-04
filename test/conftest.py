import contextlib
import os
import random
import string
import tempfile
from collections import namedtuple
from unittest import mock

import pytest
import responses
from psutil import virtual_memory

import pyega3.pyega3 as pyega3
from test.mock_data_server import MockDataServer


def rand_str():
    length = random.randint(1, 127)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


@pytest.fixture(autouse=True)
def reset_pyega_api_url():
    pyega3.URL_API = ''


@pytest.fixture(autouse=True)
def reset_pyega_global_variables():
    pyega3.URL_API_TICKET = ''
    pyega3.TEMPORARY_FILES = set()
    pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = False


@pytest.fixture
def mock_server_config(reset_pyega_api_url):
    config = pyega3.ServerConfig()

    config.url_api = 'https://test.data.server'
    config.url_auth = 'https://test.auth.server/ega-openid-connect-server/token'
    config.url_api_ticket = 'https://test.ticket.server'
    config.client_secret = 'test-client-secret'

    pyega3.URL_API = config.url_api
    pyega3.URL_API_TICKET = config.url_api_ticket

    return config


@pytest.fixture
def user_has_authenticated_successfully(mock_requests, mock_server_config):
    mock_requests.add(responses.POST, mock_server_config.url_auth, json={'access_token': 'ok'}, status=200)


@pytest.fixture
def mock_requests():
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def random_binary_file():
    mem = virtual_memory().available
    file_length = random.randint(1, mem // 512)
    return os.urandom(file_length)


@pytest.fixture
def temporary_output_file():
    """Returns a file-path to a random, temporary file-name."""
    _, output_file_path = tempfile.mkstemp()
    os.remove(output_file_path)
    return output_file_path


@pytest.fixture
def mock_data_server(mock_requests, mock_server_config):
    return MockDataServer(mock_requests, mock_server_config.url_api)


@pytest.fixture
def mock_input_file():
    @contextlib.contextmanager
    def make_mock_input_file(contents):
        file_name = rand_str()
        with mock.patch('os.path.exists', lambda p: p == file_name):
            with mock.patch('builtins.open', mock.mock_open(read_data=contents)):
                yield file_name

    return make_mock_input_file


@pytest.fixture
def empty_dataset(mock_data_server):
    file_id = "EGAD00000000001"
    mock_data_server.dataset_files[file_id] = None
    Dataset = namedtuple('Dataset', ['id'])
    return Dataset(file_id)


@pytest.fixture
def dataset_with_files(mock_data_server, empty_dataset):
    files = [
        {
            "unencryptedChecksum": "3b89b96387db5199fef6ba613f70e27c",
            "datasetId": empty_dataset.id,
            "fileStatus": "available",
            "fileId": "EGAF00000000001",
            "checksumType": "MD5",
            "fileSize": 4804928,
            "fileName": "EGAZ00000000001/ENCFF000001.bam",
            "displayFileName": "ENCFF000001.bam"
        },
        {
            "unencryptedChecksum": "b8ae14d5d1f717ab17d45e8fc36946a0",
            "datasetId": empty_dataset.id,
            "fileStatus": "available",
            "fileId": "EGAF00000000002",
            "checksumType": "MD5",
            "fileSize": 5991400,
            "fileName": "EGAZ00000000002/ENCFF000002.bam",
            "displayFileName": "ENCFF000002.bam"
        }]

    for file in files:
        mock_data_server.files[file.get("fileId")] = file
    mock_data_server.dataset_files = {empty_dataset.id: [file.get("fileId") for file in files]}

    Dataset = namedtuple("DatasetWithFiles", ["id", "files"])
    return Dataset(empty_dataset.id, files)
