#!/usr/bin/env python3
"""pyEGA3 uses the EGA REST API to download authorized datasets and files."""

import argparse
import concurrent.futures
import getpass
import hashlib
import json
import logging
import logging.handlers
import math
import os
import platform
import random
import re
import sys
import time

import htsget
import psutil
import requests
from tqdm import tqdm

VERSION = "3.1.0"

LEGACY_DATASETS = ["EGAD00000000003", "EGAD00000000004", "EGAD00000000005", "EGAD00000000006", "EGAD00000000007",
                   "EGAD00000000008", "EGAD00000000009", "EGAD00000000025", "EGAD00000000029", "EGAD00000000043",
                   "EGAD00000000048", "EGAD00000000049", "EGAD00000000051", "EGAD00000000052", "EGAD00000000053",
                   "EGAD00000000054", "EGAD00000000055", "EGAD00000000056", "EGAD00000000057", "EGAD00000000060",
                   "EGAD00000000114", "EGAD00000000119", "EGAD00000000120", "EGAD00000000121", "EGAD00000000122",
                   "EGAD00001000132", "EGAD00010000124", "EGAD00010000144", "EGAD00010000148", "EGAD00010000150",
                   "EGAD00010000158", "EGAD00010000160", "EGAD00010000162", "EGAD00010000164", "EGAD00010000246",
                   "EGAD00010000248", "EGAD00010000250", "EGAD00010000256", "EGAD00010000444"]


class DownloadClient:
    """The DownloadClient uses the EGA REST API to download authorized datasets and files."""

    download_file_slice_chunk_size = 32 * 1024
    temporary_file_name_pattern = r'.+-from-\d+-len-\d+\.slice$'

    def __init__(self):
        self.logging_level = logging.INFO
        self.session_id = random.getrandbits(32)
        self.url_auth = ""
        self.url_api = ""
        self.url_api_ticket = ""
        self.client_secret = ""
        self.temporary_files = set()
        self.temporary_files_should_be_deleted = False

        self.load_default_server_config()

    def get_standard_headers(self):
        return {'Client-Version': VERSION, 'Session-Id': str(self.session_id)}

    @staticmethod
    def get_credential():
        username = input("Enter Username: ")
        password = getpass.getpass("Password for '{}': ".format(username))
        return username, password, None

    def load_credential(self, filepath):
        """Load credentials for EMBL/EBI EGA from specified file"""
        filepath = os.path.expanduser(filepath)
        if not os.path.exists(filepath):
            logging.error("{} does not exist".format(filepath))
            return self.get_credential()

        try:
            with open(filepath) as config_file:
                cfg = json.load(config_file)
            if 'username' not in cfg:
                cfg['username'] = input("Enter Username :")
            if 'password' not in cfg:
                cfg['password'] = getpass.getpass("Password for '{}':".format(cfg['username']))
        except ValueError:
            logging.error("Invalid credential config JSON file")
            sys.exit()

        return cfg['username'], cfg['password'], cfg.get('key')

    def load_default_server_config(self):
        """Load default server config for EMBL/EBI EGA from specified file"""
        root_dir = os.path.split(os.path.realpath(__file__))[0]
        server_file_path = os.path.join(root_dir, "config", "default_server_file.json")
        self.load_server_config(server_file_path)

    def load_server_config(self, filepath):
        """Load custom server config for EMBL/EBI EGA from specified file"""
        filepath = os.path.expanduser(filepath)
        if not os.path.exists(filepath):
            logging.error("{} does not exist".format(filepath))
            sys.exit()

        try:
            with open(filepath) as custom_server_config_file:
                custom_server_config = json.load(custom_server_config_file)
            if ('url_auth' not in custom_server_config or
                    'url_api' not in custom_server_config or
                    'url_api_ticket' not in custom_server_config or
                    'client_secret' not in custom_server_config):
                logging.error("{} does not contain either 'url_auth' or 'url_api' "
                              "or 'url_api_ticket' or 'client_secret' fields".format(filepath))
                sys.exit()

            self.url_auth = custom_server_config['url_auth']
            self.url_api = custom_server_config['url_api']
            self.url_api_ticket = custom_server_config['url_api_ticket']
            self.client_secret = custom_server_config['client_secret']
        except ValueError:
            logging.error("Invalid server config JSON file")
            sys.exit()

    def get_token(self, credentials):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        headers.update(self.get_standard_headers())

        (username, password) = credentials
        data = {"grant_type": "password",
                "client_id": "f20cd2d3-682a-4568-a53e-4262ef54c8f4",
                "scope": "openid",
                "client_secret": self.client_secret,
                "username": username,
                "password": password
                }

        resp = requests.post(self.url_auth, headers=headers, data=data)

        try:
            logging.info('')
            reply = resp.json()
            resp.raise_for_status()
            oauth_token = reply['access_token']
            logging.info("Authentication success for user '{}'".format(username))
        except Exception:
            logging.exception("Invalid username, password or secret key - please check and retry. "
                              "If problem persists contact helpdesk on helpdesk@ega-archive.org")
            sys.exit()

        return oauth_token

    def api_list_authorized_datasets(self, token):
        """List datasets to which the credentialed user has authorized access"""

        headers = {'Accept': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
        headers.update(self.get_standard_headers())

        url = self.url_api + "/metadata/datasets"
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()

        reply = resp.json()

        self.print_debug_info(url, reply)

        if reply is None:
            logging.error("You do not currently have access to any datasets at EGA according to our databases. "
                          "If you believe you should have access please contact helpdesk on helpdesk@ega-archive.org")
            sys.exit()

        return reply

    @staticmethod
    def pretty_print_authorized_datasets(reply):
        logging.info("Dataset ID")
        logging.info("-----------------")
        for datasetid in reply:
            logging.info(datasetid)

    def api_list_files_in_dataset(self, token, dataset):
        if dataset in LEGACY_DATASETS:
            logging.error("This is a legacy dataset {}. "
                          "Please contact the EGA helpdesk for more information.".format(dataset))
            sys.exit()

        headers = {'Accept': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
        headers.update(self.get_standard_headers())
        url = self.url_api + "/metadata/datasets/{}/files".format(dataset)

        if dataset not in self.api_list_authorized_datasets(token):
            logging.error("Dataset '{}' is not in the list of your authorized datasets.".format(dataset))
            sys.exit()

        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        logging.debug(resp)

        reply = resp.json()
        self.print_debug_info(url, reply)

        if reply is None:
            logging.error("List files in dataset {} failed".format(dataset))
            sys.exit()

        return reply

    @staticmethod
    def status_ok(status_string):
        return status_string == "available"

    def pretty_print_files_in_dataset(self, reply):
        """
        Print a table of files in authorized dataset from api call api_list_files_in_dataset

            {
               "checksumType": "MD5",
                "unencryptedChecksum": "MD5SUM678901234567890123456789012",
                "fileName": "EGAZ00001314035/b37/NA12878.bam.bai.cip",
                "displayFileName": "NA12878.bam.bai.cip",
                "fileStatus": "available",
                "fileSize": 8949984,
                "datasetId": "EGAD00001003338",
                "fileId": "EGAF00001753747"
            }

        """
        format_string = "{:15} {:6} {:12} {:36} {}"

        logging.info(format_string.format("File ID", "Status", "Bytes", "Check sum", "File name"))
        for res in reply:
            logging.info(format_string.format(res['fileId'], self.status_ok(res['fileStatus']), str(res['fileSize']),
                                              res['unencryptedChecksum'], res['displayFileName']))

        logging.info('-' * 80)
        logging.info("Total dataset size = %.2f GB " % (sum(r['fileSize'] for r in reply) / (1024 * 1024 * 1024.0)))

    def get_file_name_size_md5(self, token, file_id):
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
        headers.update(self.get_standard_headers())
        url = self.url_api + "/metadata/files/{}".format(file_id)

        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        res = resp.json()

        self.print_debug_info(url, res)

        if res['displayFileName'] is None or res['unencryptedChecksum'] is None:
            raise RuntimeError("Metadata for file id '{}' could not be retrieved".format(file_id))

        return res['displayFileName'], res['fileName'], res['fileSize'], res['unencryptedChecksum']

    def download_file_slice(self, url, token, base_file_name, start_pos, expected_length, pbar=None):
        if start_pos < 0:
            raise ValueError("start : must be positive")
        if expected_length <= 0:
            raise ValueError("length : must be positive")

        file_name = self.get_temporary_file_name(base_file_name, start_pos, expected_length)
        self.temporary_files.add(file_name)

        existing_size = os.stat(file_name).st_size if os.path.exists(file_name) else 0
        if existing_size > expected_length:
            os.remove(file_name)
        if pbar:
            pbar.update(existing_size)

        if existing_size == expected_length:
            return file_name

        headers = self.get_standard_headers()
        headers['Authorization'] = 'Bearer {}'.format(token)
        headers['Range'] = 'bytes={}-{}'.format(start_pos + existing_size, start_pos + expected_length - 1)

        with requests.get(url, headers=headers, stream=True) as resp:
            self.print_debug_info(url, None, "Response headers: {}".format(resp.headers))
            resp.raise_for_status()
            with open(file_name, 'ba') as file_out:
                for chunk in resp.iter_content(self.download_file_slice_chunk_size):
                    file_out.write(chunk)
                    if pbar:
                        pbar.update(len(chunk))

        total_received = os.path.getsize(file_name)
        if total_received != expected_length:
            raise Exception(
                "Slice error: received={}, requested={}, file='{}'".format(total_received, expected_length, file_name))

        return file_name

    def download_file_slice_(self, args):
        return self.download_file_slice(*args)

    def merge_bin_files_on_disk(self, target_file_name, files_to_merge, downloaded_file_total_size):
        logging.info('Combining file chunks (this operation can take a long time depending on the file size)')
        start = time.time()

        with tqdm(total=int(downloaded_file_total_size), unit='B', unit_scale=True) as pbar:
            os.rename(files_to_merge[0], target_file_name)
            logging.debug(files_to_merge[0])
            if pbar:
                pbar.update(os.path.getsize(target_file_name))

            with open(target_file_name, 'ab') as target_file:
                for file_name in files_to_merge[1:]:
                    with open(file_name, 'rb') as input_file:
                        logging.debug(file_name)
                        self.copyfileobj(input_file, target_file, 65536, pbar)
                    os.remove(file_name)
            pbar.close()

        end = time.time()
        logging.debug('Merged in {} sec'.format(end - start))

    @staticmethod
    def copyfileobj(f_source, f_destination, length=16 * 1024, pbar=None):
        while 1:
            buf = f_source.read(length)
            if not buf:
                break
            f_destination.write(buf)
            pbar.update(len(buf))

    @staticmethod
    def calculate_md5(fname, file_size):
        if not os.path.exists(fname):
            raise Exception("Local file '{}' does not exist".format(fname))
        hash_md5 = hashlib.md5()

        with tqdm(total=int(file_size), unit='B', unit_scale=True) as pbar:
            with open(fname, "rb") as local_file:
                for chunk in iter(lambda: local_file.read(4096), b""):
                    hash_md5.update(chunk)
                    # pbar is created 4 lines above, it always exists.
                    # TODO bjuhasz, anandmohan777: this condition is always true:
                    if pbar:
                        pbar.update(len(chunk))
            pbar.close()
        return hash_md5.hexdigest()

    @staticmethod
    def get_fname_md5(fname):
        return fname + ".md5"

    def md5(self, fname, file_size):
        fname_md5 = self.get_fname_md5(fname)
        # check if md5 has been previously stored in aux file
        if os.path.exists(fname_md5) and os.path.getsize(fname_md5) == 32:
            logging.info("Reusing pre-calculated md5: '{}'".format(fname_md5))
            with open(fname_md5, 'rb') as md5_file:
                return md5_file.read().decode()
        # now do the real calculation
        result = self.calculate_md5(fname, file_size)
        return result

    @staticmethod
    def print_local_file_info(prefix_str, file, md5_checksum):
        logging.info("{}'{}'({} bytes, md5={})"
                     .format(prefix_str, os.path.abspath(file), os.path.getsize(file), md5_checksum))

    @staticmethod
    def print_local_file_info_genomic_range(prefix_str, file, gr_args):
        logging.info(
            "{}'{}'({} bytes, referenceName={}, referenceMD5={}, start={}, end={}, format={})".format(
                prefix_str,
                os.path.abspath(file), os.path.getsize(file),
                gr_args[0], gr_args[1], gr_args[2], gr_args[3], gr_args[4])
        )

    @staticmethod
    def is_genomic_range(genomic_range_args):
        if not genomic_range_args:
            return False
        return genomic_range_args[0] is not None or genomic_range_args[1] is not None

    def generate_output_filename(self, folder, file_id, file_name, genomic_range_args):
        ext_to_remove = ".cip"
        if file_name.endswith(ext_to_remove):
            file_name = file_name[:-len(ext_to_remove)]
        name, ext = os.path.splitext(os.path.basename(file_name))

        genomic_range = ''
        if self.is_genomic_range(genomic_range_args):
            genomic_range = "_genomic_range_" + (genomic_range_args[0] or genomic_range_args[1])
            genomic_range += '_' + (str(genomic_range_args[2]) or '0')
            genomic_range += '_' + (str(genomic_range_args[3]) or '')
            format_ext = '.' + (genomic_range_args[4] or '').strip().lower()
            if format_ext != ext and len(format_ext) > 1:
                ext += format_ext

        ret_val = os.path.join(folder, file_id, name + genomic_range + ext)
        logging.debug("Output file:'{}'".format(ret_val))
        return ret_val

    def download_file(self, token, file_id, file_size, check_sum, num_connections, key, output_file=None):
        """Download an individual file"""

        if key is not None:
            raise ValueError('key parameter: encrypted downloads are not supported yet')

        url = self.url_api + "/files/{}".format(file_id)

        # TODO bjuhasz, anandmohan777: this condition is always true
        #  because of the "if key is not None" check above:
        if key is None:
            url += "?destinationFormat=plain"
            file_size -= 16  # 16 bytes IV not necessary in plain mode

        if os.path.exists(output_file) and self.md5(output_file, file_size) == check_sum:
            self.print_local_file_info('Local file exists:', output_file, check_sum)
            return

        num_connections = max(num_connections, 1)
        num_connections = min(num_connections, 128)

        if file_size < 100 * 1024 * 1024:
            num_connections = 1

        logging.info("Download starting [using {} connection(s)]...".format(num_connections))

        chunk_len = math.ceil(file_size / num_connections)

        with tqdm(total=int(file_size), unit='B', unit_scale=True) as pbar:
            params = [(url, token, output_file, chunk_start_pos, min(chunk_len, file_size - chunk_start_pos), pbar) for
                      chunk_start_pos in range(0, file_size, chunk_len)]

            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_connections) as executor:
                for part_file_name in executor.map(self.download_file_slice_, params):
                    results.append(part_file_name)

            pbar.close()

            downloaded_file_total_size = sum(os.path.getsize(f) for f in results)
            if downloaded_file_total_size == file_size:
                self.merge_bin_files_on_disk(output_file, results, downloaded_file_total_size)

        not_valid_server_md5 = len(str(check_sum or '')) != 32

        logging.info("Calculating md5 (this operation can take a long time depending on the file size)")

        received_file_md5 = self.md5(output_file, file_size)

        logging.info("Verifying file checksum")

        if received_file_md5 == check_sum or not_valid_server_md5:
            self.print_local_file_info('Saved to : ', output_file, check_sum)
            if not_valid_server_md5:
                logging.info("WARNING: Unable to obtain valid MD5 from the server(received:{}). "
                             "Can't validate download. Please contact the EGA helpdesk.".format(check_sum))
            with open(self.get_fname_md5(output_file),
                      'wb') as md5_file:  # save good md5 in aux file for future re-use
                md5_file.write(received_file_md5.encode())
        else:
            os.remove(output_file)
            raise Exception(
                "Download process expected md5 value '{}' but got '{}'".format(check_sum, received_file_md5))

    def download_file_retry(self, creds, file_id, display_file_name, file_name, file_size, check_sum, num_connections,
                            key, output_file, genomic_range_args, max_retries, retry_wait):
        time0 = time.time()
        token = self.get_token(creds)

        if file_name.endswith(".gpg"):
            logging.info("GPG files are not supported")
            return

        logging.info("File Id: '{}'({} bytes).".format(file_id, file_size))

        if output_file is None:
            output_file = self.generate_output_filename(os.getcwd(), file_id, display_file_name, genomic_range_args)
        directory = os.path.dirname(output_file)
        if not os.path.exists(directory) and len(directory) > 0:
            os.makedirs(directory)

        hdd = psutil.disk_usage(os.getcwd())
        logging.info("Total space : {:.2f} GiB".format(hdd.total / (2 ** 30)))
        logging.info("Used space : {:.2f} GiB".format(hdd.used / (2 ** 30)))
        logging.info("Free space : {:.2f} GiB".format(hdd.free / (2 ** 30)))

        if self.is_genomic_range(genomic_range_args):
            with open(output_file, 'wb') as output:
                htsget.get(
                    self.url_api_ticket + "/tickets/files/{}".format(file_id),
                    output,
                    reference_name=genomic_range_args[0], reference_md5=genomic_range_args[1],
                    start=genomic_range_args[2], end=genomic_range_args[3],
                    data_format=genomic_range_args[4],
                    max_retries=sys.maxsize if max_retries < 0 else max_retries,
                    retry_wait=retry_wait,
                    bearer_token=token)
            self.print_local_file_info_genomic_range('Saved to : ', output_file, genomic_range_args)
            return

        done = False
        num_retries = 0
        while not done:
            try:
                if time.time() - time0 > 1 * 60 * 60:  # token expires in 1 hour
                    time0 = time.time()
                    token = self.get_token(creds)
                self.download_file(token, file_id, file_size, check_sum, num_connections, key, output_file)
                done = True
            except Exception as ex:
                logging.exception(ex)

                if num_retries == max_retries:
                    if self.temporary_files_should_be_deleted:
                        self.delete_temporary_files(self.temporary_files)

                    raise ex
                time.sleep(retry_wait)
                num_retries += 1
                logging.info("retry attempt {}".format(num_retries))

    def download_dataset(self, credentials, dataset_id, num_connections, key, output_dir,
                         genomic_range_args, max_retries=5, retry_wait=5):
        if dataset_id in LEGACY_DATASETS:
            logging.error("This is a legacy dataset {}. "
                          "Please contact the EGA helpdesk for more information.".format(dataset_id))
            sys.exit()

        token = self.get_token(credentials)

        if dataset_id not in self.api_list_authorized_datasets(token):
            logging.info("Dataset '{}' is not in the list of your authorized datasets.".format(dataset_id))
            return

        reply = self.api_list_files_in_dataset(token, dataset_id)
        for res in reply:
            try:
                if self.status_ok(res['fileStatus']):
                    if output_dir is None:
                        output_file = None
                    else:
                        output_file = self.generate_output_filename(output_dir,
                                                                    res['fileId'],
                                                                    res['displayFileName'],
                                                                    genomic_range_args)

                    self.download_file_retry(
                        credentials, res['fileId'], res['displayFileName'], res['fileName'], res['fileSize'],
                        res['unencryptedChecksum'],
                        num_connections, key, output_file, genomic_range_args, max_retries, retry_wait)
            except Exception as ex:
                logging.exception(ex)

    @staticmethod
    def print_debug_info(url, reply_json, *args):
        logging.debug("Request URL : {}".format(url))
        if reply_json is not None:
            logging.debug("Response    :\n %.1200s" % json.dumps(reply_json, indent=4))

        for arg in args:
            logging.debug(arg)

    @staticmethod
    def create_parser():
        parser = argparse.ArgumentParser(description="Download from EMBL EBI's EGA (European Genome-phenome Archive)")
        parser.add_argument("-d", "--debug", action="store_true", help="Extra debugging messages")
        parser.add_argument("-cf", "--config-file", dest='config_file',
                            help='JSON file containing credentials/config e.g.{"username":"user1","password":"toor"}')
        parser.add_argument("-sf", "--server-file", dest='server_file',
                            help='JSON file containing server config e.g.{"url_auth":"aai url","url_api":"api url", '
                                 '"url_api_ticket":"htsget url", "client_secret":"client secret"}')
        parser.add_argument("-c", "--connections", type=int, default=1,
                            help="Download using specified number of connections")
        parser.add_argument("-t", "--test", action="store_true", help="Test user activated")

        subparsers = parser.add_subparsers(dest="subcommand", help="subcommands")

        subparsers.add_parser("datasets", help="List authorized datasets")

        parser_dsinfo = subparsers.add_parser("files", help="List files in a specified dataset")
        parser_dsinfo.add_argument("identifier", help="Dataset ID (e.g. EGAD00000000001)")

        parser_fetch = subparsers.add_parser("fetch", help="Fetch a dataset or file")
        parser_fetch.add_argument("identifier", help="Id for dataset (e.g. EGAD00000000001) "
                                                     "or file (e.g. EGAF12345678901)")

        parser_clean = subparsers.add_parser("clean", help="Delete temporary files created during download")
        parser_clean.add_argument("--directory", "-dir", type=str, default=None,
                                  help="The directory from which the temporary files should be deleted. "
                                       "If not specified, the current directory will be used.")

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
            help="The maximum number of times to retry a failed transfer. "
                 "Any negative number means infinite number of retries.")

        parser_fetch.add_argument("--delete-temp-files", action="store_true",
                                  help="Do not keep those temporary, partial files "
                                       "which were left on the disk after a failed transfer.")

        parser_fetch.add_argument(
            "--retry-wait", "-W", type=float, default=60,
            help="The number of seconds to wait before retrying a failed transfer.")

        parser_fetch.add_argument("--saveto", nargs='?', help="Output file(for files)/output dir(for datasets)")

        return parser

    def run_commands(self, args):
        if args.debug:
            self.logging_level = logging.DEBUG

        logging.basicConfig(level=self.logging_level, format='%(asctime)s %(message)s',
                            datefmt='[%Y-%m-%d %H:%M:%S %z]',
                            handlers=[
                                logging.handlers.RotatingFileHandler("pyega3_output.log", maxBytes=5 * 1024 * 1024,
                                                                     backupCount=1),
                                logging.StreamHandler()
                            ])

        logging.info("")
        logging.info("pyEGA3 - EGA python client version {} "
                     "(https://github.com/EGA-archive/ega-download-client)".format(VERSION))
        logging.info("Parts of this software are derived from pyEGA "
                     "(https://github.com/blachlylab/pyega) by James Blachly")
        logging.info("Python version : {}".format(platform.python_version()))
        logging.info("OS version : {} {}".format(platform.system(), platform.version()))

        root_dir = os.path.split(os.path.realpath(__file__))[0]
        config_file_path = os.path.join(root_dir, "config", "default_credential_file.json")

        if args.test:
            *credentials, key = self.load_credential(config_file_path)
        elif args.config_file is None:
            *credentials, key = self.load_credential("credential_file.json")
        else:
            *credentials, key = self.load_credential(args.config_file)

        if args.server_file is not None:
            self.load_server_config(args.server_file)

        logging.info("Server URL: {}".format(self.url_api))
        logging.info("Session-Id: {}".format(self.session_id))

        if args.subcommand == "datasets":
            token = self.get_token(credentials)
            reply = self.api_list_authorized_datasets(token)
            self.pretty_print_authorized_datasets(reply)

        # TODO bjuhasz, anandmohan777: shouldn't this be an elif?
        if args.subcommand == "files":
            if args.identifier[3] != 'D':
                logging.error("Unrecognized identifier - please use EGAD accession for dataset requests")
                sys.exit()
            token = self.get_token(credentials)
            reply = self.api_list_files_in_dataset(token, args.identifier)
            self.pretty_print_files_in_dataset(reply)

        elif args.subcommand == "fetch":
            genomic_range_args = (args.reference_name, args.reference_md5, args.start, args.end, args.format)

            if args.delete_temp_files:
                self.temporary_files_should_be_deleted = True

            if args.identifier[3] == 'D':
                self.download_dataset(credentials, args.identifier, args.connections, key, args.saveto,
                                      genomic_range_args,
                                      args.max_retries, args.retry_wait)
            elif args.identifier[3] == 'F':
                token = self.get_token(credentials)
                display_file_name, file_name, file_size, check_sum = self.get_file_name_size_md5(token, args.identifier)
                self.download_file_retry(credentials, args.identifier, display_file_name, file_name, file_size,
                                         check_sum, args.connections, key, args.saveto, genomic_range_args,
                                         args.max_retries, args.retry_wait)
            else:
                logging.error(
                    "Unrecognized identifier - please use EGAD accession for dataset request "
                    "or EGAF accession for individual file requests")
                # TODO bjuhasz, anandmohan777: should the exit status be non-zero?
                sys.exit()

            logging.info("Download complete")

        elif args.subcommand == "clean":
            self.delete_temporary_files_in_dir(args.directory)

    def main(self, args=None):
        if args is None:
            args = sys.argv[1:]

        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        self.run_commands(parsed_args)

    @staticmethod
    def delete_temporary_files(temporary_files):
        try:
            for temporary_file in temporary_files:
                logging.debug('Deleting the {} temporary file...'.format(temporary_file))
                os.remove(temporary_file)
        except FileNotFoundError as ex:
            logging.error('Could not delete the temporary file: {}'.format(ex))

    def delete_temporary_files_in_dir(self, directory='.'):
        canonical_path = os.path.realpath(directory)
        temporary_files = [os.path.join(canonical_path, file) for file in os.listdir(canonical_path)
                           if re.search(self.temporary_file_name_pattern, file)]

        print('The following temporary files will be deleted:', *temporary_files, sep='\n')
        answer = input('Do you really want to delete all of them? [y/n]')

        if answer == 'y':
            self.delete_temporary_files(temporary_files)

    def get_temporary_file_name(self, base_file_name, start_pos, length):
        temporary_file_name = '{}-from-{}-len-{}.slice'.format(base_file_name, str(start_pos), str(length))

        # pylint: disable=no-else-return
        if re.match(self.temporary_file_name_pattern, temporary_file_name):
            return temporary_file_name
        else:
            raise ValueError('The generated temporary file-name {} '
                             'does not match the pattern for temporary file-names: {}'
                             .format(temporary_file_name, self.temporary_file_name_pattern))


if __name__ == "__main__":
    download_client = DownloadClient()
    download_client.main()
