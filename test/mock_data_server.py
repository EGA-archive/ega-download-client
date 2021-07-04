import json
import re
import urllib

import responses


class MockDataServer:
    url = None
    token = None

    dataset_files = {}
    files = {}
    file_content = {}

    def __init__(self, mock_requests, url, token):
        self.url = url
        self.token = token

        mock_requests.add_callback(
            responses.GET,
            self.url + "/metadata/datasets",
            callback=self.list_datasets_callback,
            content_type='application/json',
        )

        mock_requests.add_callback(
            responses.GET,
            re.compile(self.url + "/metadata/datasets/.*/files"),
            callback=self.list_files_callback,
            content_type='application/json'
        )

        mock_requests.add_callback(
            responses.GET,
            re.compile(self.url + "/metadata/files/.*"),
            callback=self.get_file_metadata_callback,
            content_type='application/json'
        )

        mock_requests.add_callback(
            responses.GET,
            re.compile(self.url + "/files/.*"),
            callback=self.download_file_callback
        )

        mock_requests.assert_all_requests_are_fired = False

    def check_auth_header(self, request):
        auth_hdr = request.headers['Authorization']
        return auth_hdr is not None and auth_hdr == 'Bearer ' + self.token

    def list_datasets_callback(self, request):
        if not self.check_auth_header(request):
            return 400, {}, json.dumps({"error_description": "invalid token"})

        return 200, {}, json.dumps(self.all_datasets)

    def list_files_callback(self, request):
        if not self.check_auth_header(request):
            return 400, {}, json.dumps({"error_description": "invalid token"})

        dataset_id = request.path_url.split('/')[-2]
        files = None
        if self.dataset_files[dataset_id] is not None:
            files = [self.files[file_id] for file_id in sorted(self.dataset_files[dataset_id])]

        return 200, {}, json.dumps(files)

    def get_file_metadata_callback(self, request):
        if not self.check_auth_header(request):
            return 400, {}, json.dumps({"error_description": "invalid token"})

        try:
            file_id = urllib.parse.urlsplit(request.url).path.split('/')[-1]
            return 200, {}, json.dumps(self.files[file_id])
        except KeyError:
            return 404, {}, None

    @staticmethod
    def parse_ranges(s):
        return tuple(map(int, re.match(r'^bytes=(\d+)-(\d+)$', s).groups()))

    def download_file_callback(self, request):
        if not self.check_auth_header(request):
            return 400, {}, json.dumps({"error_description": "invalid token"})

        file_id = urllib.parse.urlsplit(request.url).path.split('/')[-1]
        file_content = self.file_content[file_id]

        if request.headers['Range'] is not None:
            start, end = self.parse_ranges(request.headers['Range'])
            assert start < end
            return 200, {}, file_content[start:end + 1]

        return 200, {}, file_content

    @property
    def all_datasets(self):
        if self.dataset_files is None:
            return None
        return list(sorted(self.dataset_files.keys()))
