from collections import namedtuple

import pytest
import requests

import test.conftest as common
from pyega3.libs.data_file import DataFile


@pytest.fixture
def dummy_file(mock_data_server):
    file_id = "EGAF00000000001"

    file_size = 4804928
    file_name = "EGAZ00000000001/ENCFF000001.bam"
    display_file_name = "ENCFF000001.bam"
    check_sum = "3b89b96387db5199fef6ba613f70e27c"

    file = {"fileId": file_id,
            "displayFileName": display_file_name,
            "fileName": file_name,
            "fileSize": file_size,
            "unencryptedChecksum": check_sum,
            "fileStatus": "available"}

    mock_data_server.files[file_id] = file

    DummyFile = namedtuple("DummyFile", ["id", "file_size", "file_name", "display_file_name", "check_sum"])
    return DummyFile(file_id, file_size, file_name, display_file_name, check_sum)


def test_get_file_name_size_md5(mock_data_server, dummy_file, mock_data_client):
    file = DataFile(mock_data_client, dummy_file.id)
    assert file.display_name == dummy_file.display_file_name
    assert file.name == dummy_file.file_name
    assert file.size == dummy_file.file_size
    assert file.unencrypted_checksum == dummy_file.check_sum


def test_error_with_bad_token(mock_data_server, dummy_file, mock_data_client):
    bad_token = common.rand_str()
    mock_data_client.auth_client = common.MockAuthClient(bad_token)
    with pytest.raises(requests.exceptions.HTTPError):
        file = DataFile(mock_data_client, dummy_file.id)
        file.load_metadata()


def test_error_with_unknown_file(mock_data_server, mock_data_client):
    bad_file_id = "EGAF00000000000"
    with pytest.raises(requests.exceptions.HTTPError):
        file = DataFile(mock_data_client, bad_file_id)
        file.load_metadata()


def test_error_with_file_with_bad_metadata(mock_data_server, mock_data_client):
    bad_file_id = "EGAF00000000666"
    mock_data_server.files[bad_file_id] = {"fileName": None, "displayFileName": None, "unencryptedChecksum": None}
    with pytest.raises(RuntimeError):
        file = DataFile(mock_data_client, bad_file_id)
        file.load_metadata()
