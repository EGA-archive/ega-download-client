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

def test_load_server_config_no_api_version(mock_input_file):
    config = {"url_auth": "http://url_auth",
              "url_api": "http://url_api",
              "client_secret": "secret",
              "url_api_ticket":"http://url_api_ticket",
              "url_api_stats": "http://url_api_stats"}

    with mock_input_file(json.dumps(config)) as server_config_file:
        configObject = ServerConfig.from_file(server_config_file)
        assert configObject.api_version == 1

def test_load_server_config_with_api_version(mock_input_file):
    config = {"api_version": 2,
              "url_auth": "http://url_auth",
              "url_api": "http://url_api",
              "client_secret": "secret",
              "url_api_ticket":"http://url_api_ticket",
              "url_api_stats":"http://url_api_stats",}

    with mock_input_file(json.dumps(config)) as server_config_file:
        configObject = ServerConfig.from_file(server_config_file)
        assert configObject.api_version == 2
