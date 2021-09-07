import logging
import sys
import time

import requests


class AuthClient:
    _token = None
    credentials = None
    token_expires_at = None
    token_expiry_seconds = 1 * 60 * 60  # token expires after 1 hour

    def __init__(self, url, client_secret, standard_headers):
        self.url = url
        self.client_secret = client_secret
        self.standard_headers = standard_headers

    @property
    def token(self):
        if self._token is None or time.time() >= self.token_expires_at:

            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            headers.update(self.standard_headers)

            data = {"grant_type": "password",
                    "client_id": "f20cd2d3-682a-4568-a53e-4262ef54c8f4",
                    "scope": "openid",
                    "client_secret": self.client_secret,
                    "username": self.credentials.username,
                    "password": self.credentials.password
                    }

            try:
                r = requests.post(self.url, headers=headers, data=data)
                logging.info('')
                reply = r.json()
                r.raise_for_status()
                oauth_token = reply['access_token']
                logging.info(f"Authentication success for user '{self.credentials.username}'")
            except ConnectionError:
                logging.exception(f"Could not connect to the authentication service at {self.url}. "
                                  f"Check that the necessary outbound ports are open in your firewall. "
                                  f"See the documentation for more information.")
                sys.exit()
            except Exception:
                logging.exception(
                    "Invalid username, password or secret key - please check and retry."
                    " If problem persists contact helpdesk on helpdesk@ega-archive.org")
                sys.exit()

            self._token = oauth_token
            self.token_expires_at = time.time() + self.token_expiry_seconds

        return self._token
