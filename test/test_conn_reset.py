"""
Tests the scenario when the client receives a Connection reset by the server.

Run this test: python -m unittest -v test/test_conn_reset.py
"""

import http.server
import os
import socket
import struct
import tempfile
import threading
import unittest
from http import HTTPStatus
from io import BytesIO

# pylint: disable=wrong-import-order
from requests.exceptions import ChunkedEncodingError

from pyega3 import pyega3
from test.support import threading_helper

# TODO bjuhasz: transform these global constants into local or instance variables:
CLIENT_READS_AT_ONCE = 32 * 1024
TOTAL_BYTES_WE_WANT_TO_SEND = 10 * CLIENT_READS_AT_ONCE
STOP_AFTER_X_BYTES = CLIENT_READS_AT_ONCE + 1000
_, BASE_FILE_NAME = tempfile.mkstemp()
START_POSITION = 0
OUTPUT_FILE_NAME = '{}-from-{}-len-{}.slice'.format(BASE_FILE_NAME,
                                                    str(START_POSITION),
                                                    str(TOTAL_BYTES_WE_WANT_TO_SEND))


class LoopbackHttpServer(http.server.HTTPServer):
    """HTTP server with a few modifications that make it useful for
    loopback testing purposes.
    """

    def __init__(self, server_address, request_handler_class):
        http.server.HTTPServer.__init__(self, server_address, request_handler_class)

        # Set the timeout of our listening socket really low so
        # that we can stop the server easily.
        self.socket.settimeout(0.1)

    def get_request(self):
        """HTTPServer method, overridden."""

        request, client_address = self.socket.accept()

        # It's a loopback connection, so setting the timeout
        # really low shouldn't affect anything, but should make
        # deadlocks less likely to occur.
        request.settimeout(10.0)

        return request, client_address


class LoopbackHttpServerThread(threading.Thread):
    """Stoppable thread that runs a loopback http server."""

    def __init__(self, request_handler):
        threading.Thread.__init__(self)
        self._stop_server = False
        self.ready = threading.Event()
        request_handler.protocol_version = 'HTTP/1.0'
        self.httpd = LoopbackHttpServer(('127.0.0.1', 0), request_handler)
        self.port = self.httpd.server_port

    def stop(self):
        self._stop_server = True

        self.join()
        self.httpd.server_close()

        os.remove(OUTPUT_FILE_NAME)

    def run(self):
        self.ready.set()
        while not self._stop_server:
            self.httpd.handle_request()


class ResettingHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Simple HTTP request handler with GET command.

    Serves random bytes, then it closes the connection,
    causing the client to receive a 'Connection reset by peer' error.
    """

    def do_GET(self):
        input_file = BytesIO(bytearray(os.urandom(TOTAL_BYTES_WE_WANT_TO_SEND)))

        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'application/octet-stream')
        self.send_header('Content-Length', TOTAL_BYTES_WE_WANT_TO_SEND)
        self.end_headers()

        self.send_data_to_client(input_file, STOP_AFTER_X_BYTES)
        self.reset_connection_to_client()

    def send_data_to_client(self, input_file, length_to_copy, buffer_length=CLIENT_READS_AT_ONCE):
        length_of_data_already_copied = 0
        while length_of_data_already_copied < length_to_copy:
            buffer = input_file.read(buffer_length)
            length_of_data_already_copied += len(buffer)
            if not buffer:
                break
            self.wfile.write(buffer)

    def reset_connection_to_client(self):
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self.connection.close()


class ResettingHTTPRequestHandlerTests(unittest.TestCase):
    """Tests the scenario when the client receives a Connection reset by the server."""

    def setUp(self):
        super(ResettingHTTPRequestHandlerTests, self).setUp()

        self.server = LoopbackHttpServerThread(ResettingHTTPRequestHandler)
        self.addCleanup(self.stop_server)
        self.server_url = 'http://127.0.0.1:{}'.format(self.server.port)
        self.server.start()
        self.server.ready.wait()

        try:
            os.remove(OUTPUT_FILE_NAME)
        except OSError:
            pass

    def stop_server(self):
        self.server.stop()
        self.server = None

    def test_the_connection_of_the_client_is_reset_by_the_server(self):
        with self.assertRaises(ChunkedEncodingError) as context_manager:
            client = pyega3.DownloadClient()
            client.download_file_slice(self.server_url,
                                       'Token',
                                       BASE_FILE_NAME,
                                       START_POSITION,
                                       TOTAL_BYTES_WE_WANT_TO_SEND)

        exception_message = str(context_manager.exception)
        self.assertIn('Connection reset by peer', exception_message)

        output_file_size = os.stat(OUTPUT_FILE_NAME).st_size
        self.assertEqual(output_file_size, 2 * CLIENT_READS_AT_ONCE)


THREADS_KEY = None


# pylint: disable=invalid-name
def setUpModule():
    # Store the threading_setup in a key and ensure that it is cleaned up
    # in the tearDown
    global THREADS_KEY
    THREADS_KEY = threading_helper.threading_setup()


# pylint: disable=invalid-name
def tearDownModule():
    if THREADS_KEY:
        threading_helper.threading_cleanup(*THREADS_KEY)


if __name__ == "__main__":
    unittest.main()
