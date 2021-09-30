import contextlib
import hashlib
import os
import random
import string
import tempfile
from collections import namedtuple
from unittest import mock

import pytest
import responses
from psutil import virtual_memory

from pyega3.libs.data_client import DataClient
from pyega3.libs.server_config import ServerConfig
from test.mock_data_server import MockDataServer


def rand_str():
    length = random.randint(1, 127)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


@pytest.fixture
def mock_server_config():
    return ServerConfig(url_api='https://test.data.server',
                        url_auth='https://test.auth.server/ega-openid-connect-server/token',
                        url_api_ticket='https://test.ticket.server',
                        client_secret='test-client-secret')


@pytest.fixture
def user_has_authenticated_successfully(mock_requests, mock_server_config):
    mock_requests.add(responses.POST, mock_server_config.url_auth, json={'access_token': 'ok'}, status=200)


class MockAuthClient:
    credentials = None

    def __init__(self, token=None):
        if token is None:
            token = ''.join(random.choices(string.ascii_letters, k=64))
        self.token = token


@pytest.fixture
def mock_auth_client():
    return MockAuthClient()


@pytest.fixture
def mock_data_client(mock_server_config, mock_auth_client):
    return DataClient(mock_server_config.url_api, mock_server_config.url_api_ticket, mock_auth_client, {})


@pytest.fixture
def mock_requests():
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def random_binary_file():
    mem = virtual_memory().available
    file_length = random.randint(1, mem // 512)
    return os.urandom(file_length)


another_random_binary_file = random_binary_file


@pytest.fixture
def temporary_output_file():
    """Returns a file-path to a random, temporary file-name."""
    _, output_file_path = tempfile.mkstemp()
    os.remove(output_file_path)
    return output_file_path


@pytest.fixture
def mock_data_server(mock_requests, mock_server_config, mock_auth_client):
    return MockDataServer(mock_requests, mock_server_config.url_api, mock_auth_client.token)


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


def mock_dataset_file(dataset_id, file_id, file_name, display_file_name, file_content):
    unencrypted_checksum = hashlib.md5(file_content).hexdigest()
    return {
        "unencryptedChecksum": unencrypted_checksum,
        "datasetId": dataset_id,
        "fileStatus": "available",
        "fileId": file_id,
        "checksumType": "MD5",
        "fileSize": len(file_content) + 16,
        "fileName": file_name,
        "displayFileName": display_file_name,
        "fileContent": file_content
    }


@pytest.fixture
def mock_dataset_files(empty_dataset, random_binary_file, another_random_binary_file):
    return [
        mock_dataset_file(empty_dataset.id, "EGAF00000000001",
                          "EGAZ00000000001/ENCFF000001.bam",
                          "ENCFF000001.bam", random_binary_file),
        mock_dataset_file(empty_dataset.id, "EGAF00000000002",
                          "EGAZ00000000002/ENCFF000002.bam",
                          "ENCFF000002.bam", another_random_binary_file)
    ]


@pytest.fixture
def dataset_with_files(mock_data_server, empty_dataset, mock_dataset_files):
    files = mock_dataset_files
    for file in files:
        # The file.pop("fileContent") call would change the original mock_dataset_file object,
        # which I avoid now by using copy():
        file = file.copy()
        file_id = file.get("fileId")
        mock_data_server.file_content[file_id] = file.pop("fileContent")
        mock_data_server.files[file_id] = file
    mock_data_server.dataset_files = {empty_dataset.id: [file.get("fileId") for file in files]}

    Dataset = namedtuple("DatasetWithFiles", ["id", "files"])
    return Dataset(empty_dataset.id, files)
