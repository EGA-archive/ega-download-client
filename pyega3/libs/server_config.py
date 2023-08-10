import json
import logging
import os
import sys


class ServerConfig:
    url_api = None
    url_auth = None
    url_api_ticket = None
    client_secret = None

    def __init__(self, api_version, url_api, url_auth, url_api_metadata, url_api_ticket, url_api_stats, client_secret):
        self.api_version = api_version
        self.url_api = url_api
        self.url_auth = url_auth
        self.url_api_metadata = url_api_metadata
        self.url_api_ticket = url_api_ticket
        self.url_api_stats = url_api_stats
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

            api_version = 1 if 'api_version' not in custom_server_config else custom_server_config['api_version']

            check_key('url_auth')
            check_key('url_api')
            check_key('url_api_ticket')
            check_key('client_secret')
            # Do not check url_api_metadata, it is optional

            return ServerConfig(api_version,
                                custom_server_config['url_api'],
                                custom_server_config['url_auth'],
                                custom_server_config['url_api_metadata'] if 'url_api_metadata' in custom_server_config else None,
                                custom_server_config['url_api_ticket'],
                                custom_server_config['url_api_stats'],
                                custom_server_config['client_secret'])

        except ValueError:
            logging.error("Invalid server config JSON file")
            sys.exit()
