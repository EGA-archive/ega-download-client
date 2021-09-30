import hashlib
import logging
import logging.handlers
import os
import time

import requests
from tqdm import tqdm


def merge_bin_files_on_disk(target_file_name, files_to_merge, downloaded_file_total_size):
    logging.info('Combining file chunks (this operation can take a long time depending on the file size)')
    start = time.time()

    with tqdm(total=int(downloaded_file_total_size), unit='B', unit_scale=True) as pbar:
        os.rename(files_to_merge[0], target_file_name)
        logging.debug(files_to_merge[0])
        if pbar:
            pbar.update(os.path.getsize(target_file_name))

        with open(target_file_name, 'ab') as target_file:
            for file_name in files_to_merge[1:]:
                with open(file_name, 'rb') as f:
                    logging.debug(file_name)
                    copyfileobj(f, target_file, 65536, pbar)
                os.remove(file_name)
        pbar.close()

    end = time.time()
    logging.debug(f'Merged in {end - start} sec')


def copyfileobj(f_source, f_destination, length=16 * 1024, pbar=None):
    while 1:
        buf = f_source.read(length)
        if not buf:
            break
        f_destination.write(buf)
        pbar.update(len(buf))


def calculate_md5(fname, file_size):
    if not os.path.exists(fname):
        raise Exception(f"Local file '{fname}' does not exist")
    hash_md5 = hashlib.md5()

    with tqdm(total=int(file_size), unit='B', unit_scale=True) as pbar:
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                if pbar:
                    pbar.update(len(chunk))
        pbar.close()
    return hash_md5.hexdigest()


def get_fname_md5(fname):
    return fname + ".md5"


def md5(fname, file_size):
    fname_md5 = get_fname_md5(fname)
    # check if md5 has been previously stored in aux file
    if os.path.exists(fname_md5) and os.path.getsize(fname_md5) == 32:
        logging.info(f"Reusing pre-calculated md5: '{fname_md5}'")
        with open(fname_md5, 'rb') as f:
            return f.read().decode()
    # now do the real calculation
    result = calculate_md5(fname, file_size)
    return result


def status_ok(status_string):
    if status_string == "available":
        return True
    else:
        return False


def get_client_ip():
    endpoint = 'https://ipinfo.io/json'
    unknown_status = 'Unknown'
    try:
        response = requests.get(endpoint, verify=True)
        if response.status_code != 200:
            print('Status:', response.status_code, 'Problem with the request.')
            return unknown_status

        data = response.json()
        return data['ip']
    except Exception:
        logging.error("Failed to obtain IP address")
        return unknown_status


def verify_output_dir(output_dir):
    """
    Checks whether the directory, specified by the "output_dir" parameter,
    exists or not. If "output_dir" points to a non-existent directory,
    then a NotADirectoryError exception is thrown, otherwise the absolute path
    of that directory is returned.
    """
    absolut_path_of_output_dir = os.path.abspath(output_dir)

    if os.path.isdir(absolut_path_of_output_dir):
        return absolut_path_of_output_dir
    else:
        raise NotADirectoryError(f'The "{output_dir}" directory, which was specified by the --output-dir '
                                 'command-line argument, is not an existing directory. '
                                 'Please either create that directory or specify a different one.')
