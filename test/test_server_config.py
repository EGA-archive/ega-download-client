import json

import pytest

import pyega3.pyega3 as pyega3
import test.conftest as common


def test_load_server_config_invalid_path():
    with pytest.raises(SystemExit):
        pyega3.load_server_config("/invalidpath");


def test_load_server_config_invalid_json(mock_input_file):
    with mock_input_file("bad json") as server_config_file:
        with pytest.raises(SystemExit):
            pyega3.load_server_config(server_config_file)


def test_load_server_config_missing_attributes_in_json_file(mock_input_file):
    config = {"url_auth": common.rand_str(), "url_api": common.rand_str()}

    with mock_input_file(json.dumps(config)) as server_config_file:
        with pytest.raises(SystemExit):
            pyega3.load_server_config(server_config_file)
