import logging
import threading
import time
from urllib.parse import urljoin

import requests

from pyega3.libs.error import AuthenticationError

TOKEN_REFRESH_MAX_ATTEMPTS = 3
TOKEN_REFRESH_BACKOFF_SECONDS = 1
TOKEN_REFRESH_TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}


class AuthClient:
    _token = None
    _user_id = None
    credentials = None
    token_expires_at = None
    token_expiry_seconds = 1 * 60 * 60  # token expires after 1 hour

    def __init__(self, url, client_secret, standard_headers):
        self.url = url
        self.client_secret = client_secret
        self.standard_headers = standard_headers
        self._token_condition = threading.Condition()
        self._token_refreshing = False
        self._token_refresh_error = None
        self._token_refresh_waiters = 0

    def _token_expired(self):
        return self._token is None or self.token_expires_at is None or time.time() >= self.token_expires_at

    @property
    def token(self):
        if not self._token_expired():
            return self._token

        with self._token_condition:
            if not self._token_expired():
                return self._token

            if self._token_refreshing:
                self._token_refresh_waiters += 1
                try:
                    while self._token_refreshing:
                        self._token_condition.wait()
                    refresh_error = self._token_refresh_error
                finally:
                    self._token_refresh_waiters -= 1
                    if self._token_refresh_waiters == 0:
                        self._token_refresh_error = None

                if refresh_error is not None:
                    raise AuthenticationError(str(refresh_error)) from refresh_error
                return self._token

            if self._token_refresh_error is not None and self._token_refresh_waiters > 0:
                refresh_error = self._token_refresh_error
                raise AuthenticationError(str(refresh_error)) from refresh_error

            self._token_refresh_error = None
            self._token_refreshing = True

        try:
            self._refresh_token()
        except Exception as exc:
            refresh_error = exc if isinstance(exc, AuthenticationError) else AuthenticationError(
                "Authentication refresh failed unexpectedly."
            )
            with self._token_condition:
                self._token_refresh_error = refresh_error
                self._token_refreshing = False
                self._token_condition.notify_all()
            if refresh_error is exc:
                raise
            raise refresh_error from exc

        with self._token_condition:
            self._token_refresh_error = None
            self._token_refreshing = False
            self._token_condition.notify_all()

        return self._token

    def _refresh_token(self):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        headers.update(self.standard_headers)
        data = {
            "grant_type": "password",
            "client_id": "f20cd2d3-682a-4568-a53e-4262ef54c8f4",
            "scope": "openid",
            "client_secret": self.client_secret,
            "username": self.credentials.username,
            "password": self.credentials.password
        }

        for attempt in range(1, TOKEN_REFRESH_MAX_ATTEMPTS + 1):
            try:
                response = requests.post(self.url, headers=headers, data=data, timeout=(30, 60))
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                if attempt == TOKEN_REFRESH_MAX_ATTEMPTS:
                    raise AuthenticationError(
                        f"Authentication service at {self.url} is unavailable after {attempt} attempts."
                    ) from exc
                logging.warning(
                    "Authentication service request failed; retrying (%d/%d): %s",
                    attempt, TOKEN_REFRESH_MAX_ATTEMPTS, exc
                )
                time.sleep(TOKEN_REFRESH_BACKOFF_SECONDS * (2 ** (attempt - 1)))
                continue

            if self._credentials_rejected(response):
                raise AuthenticationError(
                    "Authentication rejected the username, password or secret key. "
                    "Please check the credentials and retry."
                )

            if response.status_code in TOKEN_REFRESH_TRANSIENT_STATUS_CODES:
                if attempt == TOKEN_REFRESH_MAX_ATTEMPTS:
                    raise AuthenticationError(
                        f"Authentication service failed with HTTP {response.status_code} "
                        f"after {attempt} attempts."
                    )
                logging.warning(
                    "Authentication service returned HTTP %d; retrying (%d/%d)",
                    response.status_code, attempt, TOKEN_REFRESH_MAX_ATTEMPTS
                )
                time.sleep(TOKEN_REFRESH_BACKOFF_SECONDS * (2 ** (attempt - 1)))
                continue

            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                raise AuthenticationError(
                    f"Authentication service failed with HTTP {response.status_code}."
                ) from exc

            try:
                oauth_token = response.json()['access_token']
                if not oauth_token:
                    raise ValueError('empty access token')
            except (KeyError, TypeError, ValueError) as exc:
                raise AuthenticationError(
                    "Authentication service returned an invalid token response."
                ) from exc

            logging.info('')
            logging.info(f"Authentication success for user '{self.credentials.username}'")
            self._token = oauth_token
            self.token_expires_at = time.time() + self.token_expiry_seconds
            return

    @staticmethod
    def _credentials_rejected(response):
        if response.status_code in (401, 403):
            return True
        if response.status_code != 400:
            return False
        try:
            error = response.json().get('error')
        except (AttributeError, ValueError):
            return False
        return error in {'access_denied', 'invalid_client', 'invalid_grant', 'unauthorized_client'}

    @property
    def user_id(self):
        if not self._user_id:
            headers = {'Accept': 'application/json', 'Authorization': f'Bearer {self.token}'}
            user_info_url = urljoin(self.url, 'userinfo')
            r = requests.post(user_info_url, headers=headers, timeout=(30, 60))
            r.raise_for_status()
            reply = r.json()
            self._user_id = reply.get('sub')
        return self._user_id
