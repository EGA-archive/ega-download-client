import json

import pytest

from pyega3.libs.server_config import ServerConfig


def test_load_server_config_invalid_path():
    with pytest.raises(SystemExit):
        ServerConfig.from_file("/invalidpath");


def test_load_server_config_invalid_json(mock_input_file):
    with mock_input_file("bad json") as server_config_file:
        with pytest.raises(SystemExit):
            ServerConfig.from_file(server_config_file)


def test_load_server_config_missing_attributes_in_json_file(mock_input_file):
    config = {"url_auth": "http://url_auth", "url_api": "http://url_api"}

    with mock_input_file(json.dumps(config)) as server_config_file:
        with pytest.raises(SystemExit):
            ServerConfig.from_file(server_config_file)
