import contextlib
import json
import logging

import requests
from requests import Session
from requests.adapters import HTTPAdapter, DEFAULT_POOLSIZE
from urllib3.util import retry

from pyega3.libs.stats import Stats


def create_session_with_retry(retry_policy: retry.Retry = None, pool_max_size=None) -> Session:
    retry_policy = retry_policy or retry.Retry(
        status_forcelist=[429, 500, 503, 504],
        # status is the no. of retries if response is in status_forcelist
        status=10,
        # total has a default value of 10,
        # need to set total to a number higher than status so it'll respect the status retry count
        total=20,
        # do not retry connection errors
        connect=False,
        read=10,
        # 0.3, 0.6, 1.2, 2.4, 4.8, 9.6, 19.2, 38.4, 76.8, 120 is the BACKOFF_MAX in Retry
        backoff_factor=0.6
    )
    session = Session()
    POOL_MAX_SIZE = max(DEFAULT_POOLSIZE, pool_max_size or 0)
    adapter = HTTPAdapter(max_retries=retry_policy, pool_maxsize=POOL_MAX_SIZE)
    session.mount('https://', adapter)
    return session


class DataClient:

    def __init__(self, data_url, htsget_url, stats_url, auth_client, standard_headers, connections=1, metadata_url=None,
                 api_version=1):
        self.url = data_url
        self.metadata_url = metadata_url if metadata_url is not None else data_url + "/metadata"
        self.htsget_url = htsget_url
        self.stats_url = stats_url
        self.auth_client = auth_client
        self.standard_headers = standard_headers
        self.session = create_session_with_retry(pool_max_size=connections)
        self.api_version = api_version

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

        url = f"{self.metadata_url}{path}"
        r = self.session.get(url, headers=headers)
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
        request_timeout_in_sec = 1800  # 30 minutes
        # TODO The default is 2min and it is too short for receiving 100MB data
        # however is 30 min a good timeout?
        with self.session.get(url, headers=headers, stream=True, timeout=request_timeout_in_sec) as r:
            self.print_debug_info(url, None, f"Response headers: {r.headers}")
            r.raise_for_status()
            yield r

    def post_stats(self, stats: Stats):
        format = '%Y-%m-%dT%H:%M:%S'
        stats.session_id = self.standard_headers.get('Session-Id')
        stats.user_id = self.auth_client.user_id
        payload = {
            'userId': stats.user_id,
            'clientDownloadStartedAt': stats.client_download_started_at.strftime(format),
            'clientStatsCreatedAt': stats.client_stats_created_at.strftime(format),
            'fileId': stats.file_id,
            'numberOfAttempts': stats.number_of_attempts,
            'fileSizeInBytes': stats.file_size_in_bytes,
            'numberOfConnections': stats.number_of_connections,
            'sessionId': stats.session_id,
            'status': stats.status,
            'errorReason': stats.error_reason if stats.status == 'Failed' else None,
            'errorDetails': stats.error_details if stats.status == 'Failed' else None
        }

        response = self.session.post(f"{self.stats_url}", json=payload,
                                     headers={'Authorization': f'Bearer {self.auth_client.token}'})

        if response.status_code != requests.codes.ok:
            logging.warning(f'Failed to report stats to EGA: {json.dumps(payload)}')
            logging.warning(f'url: {self.stats_url}, response: {str(response.status_code)}')

        return response.json()
