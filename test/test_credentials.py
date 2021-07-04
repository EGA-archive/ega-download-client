import json
from unittest import mock

import pytest

import pyega3.pyega3 as pyega3
import test.conftest as common


def test_load_username_and_password_from_credentials_file(mock_input_file):
    username = common.rand_str()
    password = common.rand_str()

    with mock_input_file(json.dumps({"username": username, "password": password})) as credentials_file:
        result = pyega3.load_credential(credentials_file)
        assert len(result) == 3
        assert result[0] == username
        assert result[1] == password


def test_when_credentials_file_has_no_password_ask_user_for_it(mock_input_file):
    username = common.rand_str()
    password = common.rand_str()

    with mock_input_file(json.dumps({"username": username})) as credentials_file, mock.patch("getpass.getpass",
                                                                                             return_value=password):
        result = pyega3.load_credential(credentials_file)
        assert len(result) == 3
        assert result[0] == username
        assert result[1] == password


def test_error_when_credentials_file_is_bad_json(mock_input_file):
    with mock_input_file("bad json") as credentials_file:
        with pytest.raises(SystemExit):
            pyega3.load_credential(credentials_file)


def test_get_credential_prompts_user_for_username_and_password():
    username = common.rand_str()
    password = common.rand_str()

    with mock.patch('builtins.input', return_value=username):
        with mock.patch('getpass.getpass', return_value=password):
            assert pyega3.get_credential() == (username, password, None)


def test_load_credential_prompts_user_for_credentials_if_credentials_file_does_not_exist():
    username = common.rand_str()
    password = common.rand_str()

    with mock.patch('builtins.input', return_value=username):
        with mock.patch('getpass.getpass', return_value=password):
            with mock.patch('os.path.exists', return_value=False):
                assert pyega3.load_credential("unknownfile.txt") == (username, password, None)
