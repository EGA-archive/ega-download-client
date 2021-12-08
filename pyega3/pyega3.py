#!/usr/bin/env python3

import argparse
import logging
import logging.handlers
import os
import platform
import random

from pyega3.libs.auth_client import AuthClient
from pyega3.libs.credentials import Credentials
from pyega3.libs.data_client import DataClient
from pyega3.libs.server_config import ServerConfig
from pyega3.libs.utils import get_client_ip
from pyega3.libs.data_file import DataFile
from pyega3.libs.commands import execute_subcommand

version = "4.0.0"
session_id = random.getrandbits(32)
logging_level = logging.INFO


def main():
    parser = argparse.ArgumentParser(description="Download from EMBL EBI's EGA (European Genome-phenome Archive)")
    parser.add_argument("-d", "--debug", action="store_true", help="Extra debugging messages")
    parser.add_argument("-cf", "--config-file", dest='config_file',
                        help='JSON file containing credentials/config e.g.{"username":"user1","password":"toor"}')
    parser.add_argument("-sf", "--server-file", dest='server_file',
                        help='JSON file containing server config e.g.{"url_auth":"aai url","url_api":"api url", '
                             '"url_api_ticket":"htsget url", "client_secret":"client secret"}')
    parser.add_argument("-c", "--connections", type=int, default=1,
                        help="Download using specified number of connections (default: 1 connection)")
    parser.add_argument("-t", "--test", action="store_true", help="Test user activated")
    parser.add_argument("-ms", "--max-slice-size", type=int, default=DataFile.DEFAULT_SLICE_SIZE,
                        help="Set maximum size for each slice in bytes (default: 100 MB)")
    parser.add_argument("-j", "--json", action="store_true", help="Output data in JSON format instead of tables")

    subparsers = parser.add_subparsers(dest="subcommand", help="subcommands")

    parser_ds = subparsers.add_parser("datasets", help="List authorized datasets")

    parser_dsinfo = subparsers.add_parser("files", help="List files in a specified dataset")
    parser_dsinfo.add_argument("identifier", help="Dataset ID (e.g. EGAD00000000001)")

    parser_fetch = subparsers.add_parser("fetch", help="Fetch a dataset or file")
    parser_fetch.add_argument("identifier",
                              help="Id for dataset (e.g. EGAD00000000001) or file (e.g. EGAF12345678901)")

    parser_fetch.add_argument(
        "--reference-name", "-r", type=str, default=None,
        help=(
            "The reference sequence name, for example 'chr1', '1', or 'chrX'. "
            "If unspecified, all data is returned."))
    parser_fetch.add_argument(
        "--reference-md5", "-m", type=str, default=None,
        help=(
            "The MD5 checksum uniquely representing the requested reference "
            "sequence as a lower-case hexadecimal string, calculated as the MD5 "
            "of the upper-case sequence excluding all whitespace characters."))
    parser_fetch.add_argument(
        "--start", "-s", type=int, default=None,
        help=(
            "The start position of the range on the reference, 0-based, inclusive. "
            "If specified, reference-name or reference-md5 must also be specified."))
    parser_fetch.add_argument(
        "--end", "-e", type=int, default=None,
        help=(
            "The end position of the range on the reference, 0-based exclusive. If "
            "specified, reference-name or reference-md5 must also be specified."))
    parser_fetch.add_argument(
        "--format", "-f", type=str, default=None, choices=["BAM", "CRAM"], help="The format of data to request.")

    parser_fetch.add_argument(
        "--max-retries", "-M", type=int, default=5,
        help="The maximum number of times to retry a failed transfer. Any negative number means infinite number of retries.")

    parser_fetch.add_argument(
        "--retry-wait", "-W", type=float, default=60,
        help="The number of seconds to wait before retrying a failed transfer.")

    parser_fetch.add_argument("--output-dir", default=os.getcwd(),
                              help="Output directory. The files will be saved into this directory. Must exist. "
                                   "Default: the current working directory.")

    parser_fetch.add_argument("--delete-temp-files", action="store_true",
                              help="Do not keep those temporary, partial files "
                                   "which were left on the disk after a failed transfer.")

    args = parser.parse_args()
    if args.debug:
        global logging_level
        logging_level = logging.DEBUG

    logging.basicConfig(level=logging_level,
                        format='%(asctime)s %(message)s',
                        datefmt='[%Y-%m-%d %H:%M:%S %z]',
                        handlers=[
                            logging.handlers.RotatingFileHandler("pyega3_output.log",
                                                                 maxBytes=5 * 1024 * 1024,
                                                                 backupCount=1),
                            logging.StreamHandler()
                        ])

    logging.info("")
    logging.info(f"pyEGA3 - EGA python client version {version} (https://github.com/EGA-archive/ega-download-client)")
    logging.info(
        "Parts of this software are derived from pyEGA (https://github.com/blachlylab/pyega) by James Blachly")
    logging.info(f"Python version : {platform.python_version()}")
    logging.info(f"OS version : {platform.system()} {platform.version()}")
    if platform.system() == "Darwin":
        logging.info(f"MacOS version : {platform.mac_ver()[0]}")

    root_dir = os.path.split(os.path.realpath(__file__))[0]
    config_file_path = os.path.join(root_dir, "config", "default_credential_file.json")

    if args.test:
        credentials = Credentials.from_file(config_file_path)
    elif args.config_file is None:
        credentials = Credentials.from_file("credential_file.json")
    else:
        credentials = Credentials.from_file(args.config_file)

    if args.server_file is not None:
        server_config = ServerConfig.from_file(args.server_file)
    else:
        server_config = ServerConfig.from_file(ServerConfig.default_config_path())

    logging.info(f"Server URL: {server_config.url_api}")
    logging.info(f"Session-Id: {session_id}")

    standard_headers = {'Client-Version': version, 'Session-Id': str(session_id), 'client-ip': get_client_ip()}

    auth_client = AuthClient(server_config.url_auth, server_config.client_secret, standard_headers)
    auth_client.credentials = credentials

    data_client = DataClient(server_config.url_api, server_config.url_api_ticket, auth_client, standard_headers)

    execute_subcommand(args, data_client)


if __name__ == "__main__":
    main()
