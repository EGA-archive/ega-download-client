import contextlib
import json
import logging

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util import retry


def create_session_with_retry(retry_policy=None) -> Session:
    retry_policy = retry_policy or retry.Retry(
        total=50,
        connect=False,
        # seems that this has a default value of 10,
        # setting this to a very high number so that it'll respect the status retry count

        status=10,
        # status is the no. of retries if response is in status_forcelist

        status_forcelist=[429, 500, 503, 504],
        read=10,
        backoff_factor=0.6
    )
    session = Session()
    adapter = HTTPAdapter(max_retries=retry_policy)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


class DataClient:

    def __init__(self, url, htsget_url, auth_client, standard_headers):
        self.url = url
        self.htsget_url = htsget_url
        self.auth_client = auth_client
        self.standard_headers = standard_headers
        self.session = create_session_with_retry()

    @staticmethod
    def print_debug_info(url, reply_json, *args):
        logging.debug(f"Request URL : {url}")
        if reply_json is not None:
            logging.debug("Response    :\n %.1200s" % json.dumps(reply_json, indent=4))

        for a in args:
            logging.debug(a)

    def get_json(self, path):
        headers = {'Accept': 'application/json', 'Authorization': f'Bearer {self.auth_client.token}'}
        headers.update(self.standard_headers)

        url = f"{self.url}{path}"
        r = requests.get(url, headers=headers)
        r.raise_for_status()

        reply = r.json()

        self.print_debug_info(url, reply)
        return reply

    @contextlib.contextmanager
    def get_stream(self, path, extra_headers=None):
        headers = {'Authorization': f'Bearer {self.auth_client.token}'}
        headers.update(self.standard_headers)
        if extra_headers is not None:
            headers.update(extra_headers)

        url = f'{self.url}{path}'
        with self.session.get(url, headers=headers, stream=True) as r:
            self.print_debug_info(url, None, f"Response headers: {r.headers}")
            r.raise_for_status()
            yield r
