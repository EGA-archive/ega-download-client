import json
import logging
import os
import sys


class ServerConfig:
    url_api = None
    url_auth = None
    url_api_ticket = None
    client_secret = None

    def __init__(self, url_api, url_auth, url_api_ticket, client_secret):
        self.url_api = url_api
        self.url_auth = url_auth
        self.url_api_ticket = url_api_ticket
        self.client_secret = client_secret

    @staticmethod
    def default_config_path():
        root_dir = os.path.split(os.path.realpath(__file__))[0]
        return os.path.join(root_dir, "../config", "default_server_file.json")

    @staticmethod
    def from_file(filepath):
        """Load server config for EMBL/EBI EGA from specified file"""
        filepath = os.path.expanduser(filepath)
        if not os.path.exists(filepath):
            logging.error(f"{filepath} does not exist")
            sys.exit()

        try:
            with open(filepath) as f:
                custom_server_config = json.load(f)

            def check_key(key):
                if key not in custom_server_config:
                    logging.error(f"{filepath} does not contain '{key}' field")
                    sys.exit()

            check_key('url_auth')
            check_key('url_api')
            check_key('url_api_ticket')
            check_key('client_secret')

            return ServerConfig(custom_server_config['url_api'],
                                custom_server_config['url_auth'],
                                custom_server_config['url_api_ticket'],
                                custom_server_config['client_secret'])

        except ValueError:
            logging.error("Invalid server config JSON file")
            sys.exit()
