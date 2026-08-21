import logging
import logging.handlers
import os
import queue
import re
import shutil
import statistics
import sys
import threading
import time
import urllib
from datetime import datetime

import htsget
import requests
import psutil
from tqdm import tqdm

from pyega3.libs import utils
from pyega3.libs.error import AuthenticationError, DataFileError, SliceError, MD5MismatchError, MaxRetriesReachedError
from pyega3.libs.stats import Stats

from pyega3.libs.file_format import is_bam_or_cram_file, autocorrect_format_in_genomic_range_args

DOWNLOAD_FILE_MEMORY_BUFFER_SIZE = 32 * 1024
SLICE_DOWNLOAD_MAX_ATTEMPTS = 3
SLICE_PROGRESS_BASELINE_MIN_SAMPLES = 5
SLICE_PROGRESS_BASELINE_WINDOW = 20
SLICE_PROGRESS_CHECK_SECONDS = 15
SLICE_PROGRESS_MIN_RATE_RATIO = 0.02
SLICE_PROGRESS_DEGRADED_SECONDS = 90

SUPPORTED_FILE_FORMATS = ["BAM", "CRAM", "VCF", "BCF"]


def _make_slice_progress_guard(get_baseline_rate):
    checkpoint_time = time.monotonic()
    checkpoint_bytes = 0
    degraded_since = None

    def check_progress(total_received):
        nonlocal checkpoint_time, checkpoint_bytes, degraded_since

        now = time.monotonic()
        elapsed = now - checkpoint_time
        if elapsed < SLICE_PROGRESS_CHECK_SECONDS:
            return

        recent_bytes = total_received - checkpoint_bytes
        recent_rate = recent_bytes / elapsed
        checkpoint_time = now
        checkpoint_bytes = total_received

        baseline_rate = get_baseline_rate()
        if baseline_rate is None:
            degraded_since = None
            return

        minimum_healthy_rate = baseline_rate * SLICE_PROGRESS_MIN_RATE_RATIO
        if recent_rate >= minimum_healthy_rate:
            degraded_since = None
            return

        if degraded_since is None:
            degraded_since = now
            return

        degraded_for = now - degraded_since
        if degraded_for >= SLICE_PROGRESS_DEGRADED_SECONDS:
            ratio = recent_rate / baseline_rate
            raise SliceError(
                f"Slice progress is pathologically slow: recent={recent_rate:.0f} B/s, "
                f"baseline={baseline_rate:.0f} B/s, ratio={ratio:.4f}, "
                f"degraded_for={degraded_for:.0f}s"
            )

    return check_progress


class DataFile:
    DEFAULT_SLICE_SIZE = 100 * 1024 * 1024
    temporary_files_should_be_deleted = False

    def __init__(self, data_client, file_id,
                 display_file_name=None,
                 file_name=None,
                 size=None,
                 unencrypted_checksum=None,
                 status=None):
        self.data_client = data_client
        self.id = file_id

        self.temporary_files = set()

        self._display_file_name = display_file_name
        self._file_name = file_name
        self._file_size = size
        self._unencrypted_checksum = unencrypted_checksum
        self._file_status = status

    @staticmethod
    def from_metadata(data_client, metadata):
        file_id = metadata['fileId']
        result = DataFile(data_client, file_id)
        result._set_metadata_from_json(metadata)
        return result

    def load_metadata(self):
        res = self.data_client.get_json(f"/files/{self.id}")

        # If the user does not have access to the file then the server returns HTTP code 200 but the JSON payload has
        # all the fields empty
        if self.data_client.api_version < 2 and (res['displayFileName'] is None or res['unencryptedChecksum'] is None):
            raise RuntimeError(f"Metadata for file id '{self.id}' could not be retrieved. " +
                               "This is probably because your account does not have access to this file. "
                               "You can check which datasets your account has access to at "
                               "'https://ega-archive.org/my-datasets.php' after logging in.")

        self._set_metadata_from_json(res)

    def _set_metadata_from_json(self, res):
        self._display_file_name = res['displayFileName'] if 'displayFileName' in res else None
        self._file_name = res['fileName'] if 'fileName' in res else None
        self._file_size = res['fileSize'] if 'fileSize' in res else None

        if self.data_client.api_version == 1:
            self._unencrypted_checksum = res['unencryptedChecksum'] if 'unencryptedChecksum' in res else None

        elif self.data_client.api_version == 2:
            self._unencrypted_checksum = res['plainChecksum'] if 'plainChecksum' in res else None

        self._file_status = res['fileStatus'] if 'fileStatus' in res else None

    @property
    def display_name(self):
        if self._display_file_name is None:
            self.load_metadata()
        return self._display_file_name

    @property
    def name(self):
        if self._file_name is None:
            self.load_metadata()
        return self._file_name

    @property
    def size(self):
        if self._file_size is None:
            self.load_metadata()
        return self._file_size

    @property
    def unencrypted_checksum(self):
        if self._unencrypted_checksum is None:
            self.load_metadata()
        return self._unencrypted_checksum

    @property
    def status(self):
        if self._file_status is None:
            self.load_metadata()
        return self._file_status

    @staticmethod
    def print_local_file_info(prefix_str, file, md5):
        logging.info(f"{prefix_str}'{os.path.abspath(file)}'({os.path.getsize(file)} bytes, md5={md5})")

    def download_file(self, output_file, num_connections=1, max_slice_size=DEFAULT_SLICE_SIZE):
        """Download an individual file"""

        file_size = self.size
        check_sum = self.unencrypted_checksum
        options = {"destinationFormat": "plain"}

        file_size -= 16  # 16 bytes IV not necessary in plain mode

        num_connections = max(num_connections, 1)
        num_connections = min(num_connections, 128)

        if file_size < max_slice_size:
            num_connections = 1

        logging.info(f"Download starting [using {num_connections} connection(s), file size {file_size} and chunk "
                     f"length {max_slice_size}]...")

        chunk_len = max_slice_size

        temporary_directory = os.path.join(os.path.dirname(output_file), ".tmp_download")
        os.makedirs(temporary_directory, exist_ok=True)

        with tqdm(total=int(file_size), unit='B', unit_scale=True) as pbar:
            params = [
                (os.path.join(temporary_directory, self.id), chunk_start_pos,
                 min(chunk_len, file_size - chunk_start_pos), options, pbar)
                for chunk_start_pos in range(0, file_size, chunk_len)]

            for file in os.listdir(temporary_directory):
                match = re.match(r"(.*)-from-(\d*)-len-(\d*).*", file)
                file_id = match.group(1)
                file_from = match.group(2)
                file_length = match.group(3)

                if file_id != self.id:
                    continue

                if (int(file_from), int(file_length)) in [(param[1], param[2]) for param in params]:
                    continue

                logging.warning(f'Deleting the leftover {file} temporary file because the MAX_SLICE_SIZE parameter ('
                                f'and thus the slice sizes) have been modified since the last run.')
                os.remove(os.path.join(temporary_directory, file))

            results = self._download_file_slices(params, num_connections)

            pbar.close()

            downloaded_file_total_size = sum(os.path.getsize(f) for f in results)
            if downloaded_file_total_size != file_size:
                raise SliceError(
                    f"Downloaded slices total {downloaded_file_total_size} bytes; expected {file_size} bytes"
                )
            received_file_md5 = utils.merge_bin_files_on_disk(
                output_file, results, downloaded_file_total_size
            )

        not_valid_server_md5 = len(str(check_sum or '')) != 32

        logging.info("Verifying file checksum")

        if received_file_md5 == check_sum or not_valid_server_md5:
            DataFile.print_local_file_info('Saved to : ', output_file, check_sum)
            if not_valid_server_md5:
                logging.info(
                    f"WARNING: Unable to obtain valid MD5 from the server (received: {check_sum})."
                    f" Can't validate download. Please contact EGA helpdesk on helpdesk@ega-archive.org")
            with open(utils.get_fname_md5(output_file), 'wb') as f:  # save good md5 in aux file for future re-use
                f.write(received_file_md5.encode())

        else:
            os.remove(output_file)
            raise MD5MismatchError(f"Download process expected md5 value '{check_sum}' but got '{received_file_md5}'")

    def does_file_exist(self, output_file):
        return os.path.exists(output_file) and utils.md5(output_file, self.size) == self.unencrypted_checksum

    def _download_file_slices(self, params, num_workers):
        num_workers = min(max(num_workers, 1), len(params))
        jobs = queue.Queue()
        results = [None] * len(params)
        failures = queue.Queue()
        cancelled = threading.Event()
        successful_rates = []
        successful_rates_lock = threading.Lock()

        def get_baseline_rate():
            with successful_rates_lock:
                if len(successful_rates) < SLICE_PROGRESS_BASELINE_MIN_SAMPLES:
                    return None
                return statistics.median(successful_rates[-SLICE_PROGRESS_BASELINE_WINDOW:])

        def record_successful_rate(length, elapsed):
            if elapsed <= 0:
                return
            with successful_rates_lock:
                successful_rates.append(length / elapsed)
                if len(successful_rates) > SLICE_PROGRESS_BASELINE_WINDOW:
                    del successful_rates[:-SLICE_PROGRESS_BASELINE_WINDOW]

        for index, param in enumerate(params):
            jobs.put((index, param, 1))

        def worker():
            while True:
                job = jobs.get()
                try:
                    if job is None:
                        return

                    if cancelled.is_set():
                        continue

                    index, param, attempt = job
                    final_file_name = f'{param[0]}-from-{param[1]}-len-{param[2]}.slice'
                    was_cached = os.path.exists(final_file_name)
                    progress_guard = _make_slice_progress_guard(get_baseline_rate)
                    attempt_started = time.monotonic()
                    try:
                        results[index] = self.download_file_slice_((*param, progress_guard))
                        if not was_cached:
                            record_successful_rate(param[2], time.monotonic() - attempt_started)
                    except (requests.exceptions.ConnectionError,
                            requests.exceptions.Timeout,
                            requests.exceptions.ChunkedEncodingError,
                            SliceError) as exc:
                        if attempt < SLICE_DOWNLOAD_MAX_ATTEMPTS:
                            logging.warning(
                                f"Retrying slice from={param[1]} len={param[2]} "
                                f"attempt={attempt + 1}/{SLICE_DOWNLOAD_MAX_ATTEMPTS} "
                                f"after {type(exc).__name__}: {exc}"
                            )
                            jobs.put((index, param, attempt + 1))
                        else:
                            cancelled.set()
                            failures.put((index, exc, exc.__traceback__))
                    except AuthenticationError as exc:
                        cancelled.set()
                        failures.put((index, exc, exc.__traceback__))
                    except (requests.exceptions.RetryError, requests.exceptions.HTTPError) as exc:
                        cancelled.set()
                        failures.put((index, exc, exc.__traceback__))
                    except Exception as exc:
                        cancelled.set()
                        failures.put((index, exc, exc.__traceback__))
                finally:
                    jobs.task_done()

        workers = [
            threading.Thread(target=worker, name=f'pyega3-download-{index}')
            for index in range(num_workers)
        ]

        for thread in workers:
            thread.start()

        jobs.join()

        for _ in workers:
            jobs.put(None)

        for thread in workers:
            thread.join()

        if not failures.empty():
            _, exc, traceback = failures.get()
            raise exc.with_traceback(traceback)

        return results

    def download_file_slice_(self, args):
        return self.download_file_slice(*args)

    def download_file_slice(self, file_name, start_pos, length, options=None, pbar=None, progress_guard=None):
        if start_pos < 0:
            raise ValueError("start : must be positive")
        if length <= 0:
            raise ValueError("length : must be positive")

        path = f"/files/{self.id}"
        if options is not None:
            path += '?' + urllib.parse.urlencode(options)

        final_file_name = f'{file_name}-from-{str(start_pos)}-len-{str(length)}.slice'
        file_name = final_file_name + '.tmp'

        self.temporary_files.add(file_name)

        if os.path.exists(final_file_name):
            existing_size = os.stat(final_file_name).st_size
            if existing_size == length:
                pbar and pbar.update(existing_size)
                return final_file_name
            logging.warning(
                f"Deleting cached slice with invalid size: received={existing_size}, "
                f"expected={length}, file='{final_file_name}'"
            )
            os.remove(final_file_name)

        if os.path.exists(file_name):
            os.remove(file_name)

        try:
            range_start = start_pos
            range_end = start_pos + length - 1
            extra_headers = {
                'Range': f'bytes={range_start}-{range_end}'
            }

            with self.data_client.get_stream(path, extra_headers) as r:
                with open(file_name, 'ba') as file_out:
                    self.temporary_files.add(file_name)
                    total_received = 0
                    for chunk in r.iter_content(DOWNLOAD_FILE_MEMORY_BUFFER_SIZE):
                        file_out.write(chunk)
                        total_received += len(chunk)
                        pbar and pbar.update(len(chunk))
                        progress_guard and progress_guard(total_received)

            total_received = os.path.getsize(file_name)

            if total_received != length:
                raise SliceError(f"Slice error: received={total_received}, requested={length}, file='{file_name}'")

        except Exception as e:
            if os.path.exists(file_name):
                partial_size = os.path.getsize(file_name)
                pbar and pbar.update(-partial_size)
                os.remove(file_name)
            raise

        os.rename(file_name, final_file_name)

        return final_file_name

    @staticmethod
    def is_genomic_range(genomic_range_args):
        if not genomic_range_args:
            return False
        return genomic_range_args[0] is not None or genomic_range_args[1] is not None

    def generate_output_filename(self, folder, genomic_range_args):
        file_name = self.display_name
        ext_to_remove = ".cip"
        if file_name.endswith(ext_to_remove):
            file_name = file_name[:-len(ext_to_remove)]
        name, ext = os.path.splitext(os.path.basename(file_name))

        genomic_range = ''
        if DataFile.is_genomic_range(genomic_range_args):
            genomic_range = "_genomic_range_" + (genomic_range_args[0] or genomic_range_args[1])
            genomic_range += '_' + (str(genomic_range_args[2]) or '0')
            genomic_range += '_' + (str(genomic_range_args[3]) or '')
            format_ext = '.' + (genomic_range_args[4] or '').strip().lower()
            if format_ext != ext and len(format_ext) > 1:
                ext += format_ext

        ret_val = os.path.join(folder, self.id, name + genomic_range + ext)
        logging.debug(f"Output file:'{ret_val}'")
        return ret_val

    @staticmethod
    def print_local_file_info_genomic_range(prefix_str, file, gr_args):
        logging.info(
            f"{prefix_str}'{os.path.abspath(file)}'({os.path.getsize(file)} bytes, referenceName={gr_args[0]},"
            f" referenceMD5={gr_args[1]}, start={gr_args[2]}, end={gr_args[3]}, format={gr_args[4]})"
        )

    def download_file_retry(self, num_connections, output_dir, genomic_range_args, max_retries, retry_wait,
                            max_slice_size=DEFAULT_SLICE_SIZE):
        download_stats_list = []

        if self.name.endswith(".gpg"):
            logging.info(
                "GPG files are currently not supported."
                " Please email EGA Helpdesk at helpdesk@ega-archive.org")
        else:
            logging.info(f"File Id: '{self.id}'({self.size} bytes).")
            self._check_and_warn_if_file_is_bigger_than_free_space()
            output_file = self.generate_output_filename(output_dir, genomic_range_args)
            temporary_directory = self._create_temp_dir(output_file)

            if self.does_file_exist(output_file):
                DataFile.print_local_file_info('Local file exists:', output_file, self.unencrypted_checksum)
            elif DataFile.is_genomic_range(genomic_range_args):
                corrected_genomic_range_args = autocorrect_format_in_genomic_range_args(self.name,
                                                                                        genomic_range_args,
                                                                                        SUPPORTED_FILE_FORMATS)
                self._download_htsget_slice(corrected_genomic_range_args, max_retries, output_file, retry_wait)
            else:
                stats_list = self._download_whole_file_once(max_slice_size, num_connections, output_file,
                                                            temporary_directory)
                download_stats_list.extend(stats_list)

        return download_stats_list

    def _check_and_warn_if_file_is_bigger_than_free_space(self):
        hdd = psutil.disk_usage(os.getcwd())
        logging.info(f"Total space : {hdd.total / (2 ** 30):.2f} GiB")
        logging.info(f"Used space : {hdd.used / (2 ** 30):.2f} GiB")
        logging.info(f"Free space : {hdd.free / (2 ** 30):.2f} GiB")
        # If file is bigger than free space, warning
        if hdd.free < self.size:
            logging.warning(f"The size of the file that you want to download is bigger than your free space in this "
                            f"location")

    def _download_htsget_slice(self, genomic_range_args, max_retries, output_file, retry_wait):
        if self.data_client.api_version == 1:
            endpoint_type = "files"
        else:
            endpoint_type = "htsget/reads" if is_bam_or_cram_file(self.name) else "htsget/variants"
        with open(output_file, 'wb') as output:
            htsget.get(
                f"{self.data_client.htsget_url}/{endpoint_type}/{self.id}",
                output,
                reference_name=genomic_range_args[0], reference_md5=genomic_range_args[1],
                start=genomic_range_args[2], end=genomic_range_args[3],
                data_format=genomic_range_args[4],
                max_retries=sys.maxsize if max_retries < 0 else max_retries,
                retry_wait=retry_wait,
                bearer_token=self.data_client.auth_client.token)
        DataFile.print_local_file_info_genomic_range('Saved to : ', output_file, genomic_range_args)

    def _download_whole_file_once(self, max_slice_size, num_connections, output_file, temporary_directory):
        start_time = datetime.now()
        try:
            self.download_file(output_file, num_connections, max_slice_size)
        except Exception as e:
            logging.exception(e)
            error_reason, error_details = self._format_stats_error_reason(e)
            if DataFile.temporary_files_should_be_deleted:
                self.delete_temporary_folder(temporary_directory)

            failed_stats = Stats.failed(start_time, datetime.now(), self.id, 1, self.size,
                                        num_connections, error_reason, error_details)
            self._post_stats_nonfatal(failed_stats)
            if isinstance(e, AuthenticationError):
                raise
            raise MaxRetriesReachedError(f'Download failed: {str(e)}', [failed_stats]) from e

        succeeded_stats = Stats.succeeded(start_time, datetime.now(), self.id, 1, self.size, num_connections)
        self._post_stats_nonfatal(succeeded_stats)
        return [succeeded_stats]

    def _post_stats_nonfatal(self, stats):
        try:
            self.data_client.post_stats(stats)
        except Exception as exc:
            logging.warning("Unable to submit download statistics: %s", exc)

    def _create_temp_dir(self, output_file):
        temporary_directory = os.path.join(os.path.dirname(output_file), ".tmp_download")
        if not os.path.exists(temporary_directory):
            os.makedirs(temporary_directory)
        return temporary_directory

    def _format_stats_error_reason(self, e):
        error_class_name = e.__class__.__name__
        error_reason = str(e)
        if isinstance(e, DataFileError):
            error_reason = e.message
        return error_class_name, error_reason

    def delete_temporary_folder(self, temporary_directory):
        try:
            shutil.rmtree(temporary_directory)
        except FileNotFoundError as ex:
            logging.error(f'Could not delete the temporary folder: {ex}')
