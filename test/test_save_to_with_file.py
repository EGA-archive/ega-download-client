import hashlib
import logging
import os

import pytest

from pyega3.libs import utils
from pyega3.libs.data_file import DataFile

FILE_ID = 'EGAF00000000001'
DISPLAY_FILE_NAME = 'ENCFF284YOU.bam.bai'


@pytest.fixture()
def file_in_fire(mock_data_server, mock_data_client, random_binary_file, fs):
    mock_data_server.file_content[FILE_ID] = random_binary_file
    file_md5 = hashlib.md5(random_binary_file).hexdigest()
    yield DataFile(mock_data_client, FILE_ID, display_file_name=DISPLAY_FILE_NAME,
                   file_name=DISPLAY_FILE_NAME + '.cip', size=len(random_binary_file) + 16,
                   unencrypted_checksum=file_md5)


def download_file_from_fire(file_in_fire, output_dir):
    # num_connections, output_dir, genomic_range_args, max_retries, retry_wait
    file_in_fire.download_file_retry(1, output_dir, None, 2, 0)


def test_file_is_saved_into_an_existing_directory_which_was_specified_by_the_user(file_in_fire):
    """
    The user wants to download a file into a specific, user-specified directory.
    The directory exists and there is no such file in that directory yet.
    Expected: the file is downloaded into the user-specified directory
    and the file-name will be the 'displayFileName' (e.g. 'EGAF00000000001/ENCFF284YOU.bam.bai').
    """

    output_dir = 'user_specified_directory'
    os.makedirs(output_dir)

    expected_local_file_name = f'/{output_dir}/{FILE_ID}/{DISPLAY_FILE_NAME}'
    expected_local_md5_file_name = f'{expected_local_file_name}.md5'

    assert os.path.isdir(output_dir)
    assert not os.path.exists(expected_local_file_name)
    assert not os.path.exists(expected_local_md5_file_name)

    download_file_from_fire(file_in_fire, output_dir=output_dir)

    assert os.path.isfile(expected_local_file_name)
    assert os.path.isfile(expected_local_md5_file_name)


def test_file_in_directory_is_not_downloaded_again(file_in_fire, random_binary_file, caplog, fs):
    """
    When the file has correctly been downloaded already into the specified directory,
    then it is not downloaded again.
    """
    caplog.set_level(logging.INFO)
    output_dir = 'user_specified_directory_name'
    expected_local_file_name = f'/{output_dir}/{FILE_ID}/{DISPLAY_FILE_NAME}'
    expected_local_md5_file_name = f'{expected_local_file_name}.md5'

    # First I create the downloaded files to simulate a previous, successful download:
    fs.create_file(expected_local_file_name)
    fs.create_file(expected_local_md5_file_name)
    assert os.path.isdir(output_dir)

    with open(expected_local_file_name, 'wb') as fh:
        fh.write(random_binary_file)
    with open(expected_local_md5_file_name, 'w') as fh:
        fh.write(file_in_fire.unencrypted_checksum)
    # And I store their original mtimes:
    local_file_orig_mtime = os.stat(expected_local_file_name).st_mtime
    local_md5_file_orig_mtime = os.stat(expected_local_md5_file_name).st_mtime

    # The downloaded files should exist:
    assert os.path.isdir(output_dir)
    assert os.path.isfile(expected_local_file_name)
    assert os.path.isfile(expected_local_md5_file_name)

    # Let's simulate a second download into the specified directory.
    # This should not download again the files,
    # but it should print out a "Local file exists" message.
    download_file_from_fire(file_in_fire, output_dir=output_dir)

    local_file_mtime_after_download = os.stat(expected_local_file_name).st_mtime
    local_md5_file_mtime_after_download = os.stat(expected_local_md5_file_name).st_mtime

    # If the files haven't been re-downloaded again, then the mtimes should not have changed:
    assert local_file_orig_mtime == local_file_mtime_after_download
    assert local_md5_file_orig_mtime == local_md5_file_mtime_after_download

    assert f"Local file exists:'{expected_local_file_name}'" in caplog.text


def test_corrupted_file_in_a_directory_is_downloaded_again(file_in_fire, fs):
    """
    When the file has been downloaded incorrectly into a directory previously, then it is re-downloaded again.
    I don't think this happens too often, because an incorrectly downloaded file is always removed
    (or at least, it should be always removed).
    """

    output_dir = 'user_specified_directory_name'
    expected_local_file_name = f'/{output_dir}/{FILE_ID}/{DISPLAY_FILE_NAME}'
    expected_local_md5_file_name = f'{expected_local_file_name}.md5'

    # First I create a file to simulate a previous, unsuccessful download:
    fs.create_file(expected_local_file_name)
    with open(expected_local_file_name, 'w') as fh:
        fh.write('incorrect, corrupted content')

    # The downloaded file should exist, but without an .md5:
    assert os.path.isfile(expected_local_file_name)
    assert not os.path.exists(expected_local_md5_file_name)
    assert os.path.isdir(output_dir)

    # Let's simulate a second download into the specified directory.
    # This should download again the file and the .md5, this time, correctly.
    download_file_from_fire(file_in_fire, output_dir=output_dir)

    # Check that the actual MD5 of the re-downloaded file is correct:
    correct_expected_md5 = file_in_fire.unencrypted_checksum
    actual_md5 = utils.calculate_md5(expected_local_file_name, file_in_fire.size)
    assert actual_md5 == correct_expected_md5

    # The .md5 file should now exist:
    assert os.path.isfile(expected_local_md5_file_name)

    # And the content of the .md5 file should be the correct, expected one:
    with open(expected_local_md5_file_name, 'r') as fh:
        actual_md5 = fh.readline()
    assert actual_md5 == correct_expected_md5


def test_non_existing_directory_is_created(file_in_fire):
    """
    The user wants to download a file into a specific, user-specified directory.
    The directory does not exist.
    Expected: the non-existent directory is created automatically for the user,
    the file is downloaded into the user-specified directory
    and the file-name will be the 'displayFileName' (e.g. 'EGAF00000000001/ENCFF284YOU.bam.bai').
    The non-existent directory is created automatically as a (positive) side-effect of the code
    which creates the .tmp_download directory: that code creates not only the .tmp_download directory,
    but all the missing parent directories, too, including the non-existent user-specified directory.
    """

    output_dir = 'user_specified_directory'
    expected_local_file_name = f'/{output_dir}/{FILE_ID}/{DISPLAY_FILE_NAME}'
    expected_local_md5_file_name = f'{expected_local_file_name}.md5'

    assert not os.path.exists(output_dir)
    assert not os.path.exists(expected_local_file_name)
    assert not os.path.exists(expected_local_md5_file_name)

    download_file_from_fire(file_in_fire, output_dir=output_dir)

    assert os.path.isdir(output_dir)
    assert os.path.isfile(expected_local_file_name)
    assert os.path.isfile(expected_local_md5_file_name)
