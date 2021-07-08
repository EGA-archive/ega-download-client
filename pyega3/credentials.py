import getpass
import json
import logging
import os
import sys


class Credentials:
    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password

    @staticmethod
    def from_file(filepath):
        """Load credentials for EMBL/EBI EGA from specified file"""
        result = Credentials()
        filepath = os.path.expanduser(filepath)
        if not os.path.exists(filepath):
            logging.error(f"{filepath} does not exist")
        else:
            try:
                with open(filepath) as f:
                    cfg = json.load(f)

                if 'username' in cfg:
                    result.username = cfg['username']
                if 'password' in cfg:
                    result.password = cfg['password']

            except ValueError:
                logging.error("Invalid credential config JSON file")
                sys.exit()

        result.prompt_for_missing_values()

        return result

    def prompt_for_missing_values(self):
        if self.username is None:
            self.username = input("Enter Username :")
        if self.password is None:
            self.password = getpass.getpass(f"Password for '{self.username}':")