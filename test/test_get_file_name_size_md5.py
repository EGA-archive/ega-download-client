from collections import namedtuple

import pytest
import requests

import pyega3.pyega3 as pyega3
import test.conftest as common


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
            "unencryptedChecksum": check_sum}

    mock_data_server.files[file_id] = file

    DummyFile = namedtuple("DummyFile", ["id", "file_size", "file_name", "display_file_name", "check_sum"])
    return DummyFile(file_id, file_size, file_name, display_file_name, check_sum)


def test_get_file_name_size_md5(mock_data_server, dummy_file, mock_server_config):
    rv = pyega3.get_file_name_size_md5(mock_data_server.token, dummy_file.id, mock_server_config)
    assert len(rv) == 4
    assert rv[0] == dummy_file.display_file_name
    assert rv[1] == dummy_file.file_name
    assert rv[2] == dummy_file.file_size
    assert rv[3] == dummy_file.check_sum


def test_error_with_bad_token(mock_data_server, dummy_file, mock_server_config):
    bad_token = common.rand_str()
    with pytest.raises(requests.exceptions.HTTPError):
        pyega3.get_file_name_size_md5(bad_token, dummy_file.id, mock_server_config)


def test_error_with_unknown_file(mock_data_server, mock_server_config):
    bad_file_id = "EGAF00000000000"
    with pytest.raises(requests.exceptions.HTTPError):
        pyega3.get_file_name_size_md5(mock_data_server.token, bad_file_id, mock_server_config)


def test_error_with_file_with_bad_metadata(mock_data_server, mock_server_config):
    bad_file_id = "EGAF00000000666"
    mock_data_server.files[bad_file_id] = {"fileName": None, "displayFileName": None, "unencryptedChecksum": None}
    with pytest.raises(RuntimeError):
        pyega3.get_file_name_size_md5(mock_data_server.token, bad_file_id, mock_server_config)
