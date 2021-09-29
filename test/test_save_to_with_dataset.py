import os

import pytest

from pyega3.libs import utils
from pyega3.libs.data_set import DataSet

OUTPUT_DIR = 'user_specified_directory'
EXPECTED_FILE_PATHS = [
    f'/{OUTPUT_DIR}/EGAF00000000001/ENCFF000001.bam',
    f'/{OUTPUT_DIR}/EGAF00000000001/ENCFF000001.bam.md5',
    f'/{OUTPUT_DIR}/EGAF00000000002/ENCFF000002.bam',
    f'/{OUTPUT_DIR}/EGAF00000000002/ENCFF000002.bam.md5'
]


@pytest.fixture()
def dataset_in_fire(mock_data_client, dataset_with_files):
    return DataSet(mock_data_client, dataset_with_files.id)


def download_dataset_from_fire(dataset_in_fire):
    # num_connections, output_dir, genomic_range_args, max_retries=5, retry_wait=5
    dataset_in_fire.download(1, OUTPUT_DIR, None, max_retries=2, retry_wait=0)


def assert_that_expected_file_paths_not_exist():
    for expected_file_path in EXPECTED_FILE_PATHS:
        assert not os.path.exists(expected_file_path)


def assert_that_expected_file_paths_exist():
    for expected_file_path in EXPECTED_FILE_PATHS:
        assert os.path.isfile(expected_file_path)


def test_file_is_saved_into_an_existing_directory_which_was_specified_by_the_user(dataset_in_fire, fs):
    """
    The user wants to download a file into a specific, user-specified directory.
    The directory exists and there is no such file in that directory yet.
    Expected: the file is downloaded into the user-specified directory
    and the file-name will be the 'displayFileName' (e.g. 'EGAF00000000001/ENCFF284YOU.bam.bai').
    """

    os.makedirs(OUTPUT_DIR)

    assert os.path.isdir(OUTPUT_DIR)
    assert_that_expected_file_paths_not_exist()

    download_dataset_from_fire(dataset_in_fire)

    assert_that_expected_file_paths_exist()


def test_file_in_directory_is_not_downloaded_again(dataset_in_fire, fs):
    """
    When the file has correctly been downloaded already into the specified directory,
    then it is not downloaded again.
    """

    # First I create the downloaded files to simulate a previous, successful download:
    fs.create_file(expected_local_file_name)
    fs.create_file(expected_local_md5_file_name)
    assert os.path.isdir(OUTPUT_DIR)

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
    download_dataset_from_fire(file_in_fire, save_to=output_dir)

    local_file_mtime_after_download = os.stat(expected_local_file_name).st_mtime
    local_md5_file_mtime_after_download = os.stat(expected_local_md5_file_name).st_mtime

    # If the files haven't been re-downloaded again, then the mtimes should not have changed:
    assert local_file_orig_mtime == local_file_mtime_after_download
    assert local_md5_file_orig_mtime == local_md5_file_mtime_after_download


def test_corrupted_file_in_a_directory_is_downloaded_again(file_in_fire, fs):
    """
    When the file has been downloaded incorrectly into a directory previously, then it is re-downloaded again.
    I don't think this happens too often, because an incorrectly downloaded file is always removed
    (or at least, it should be removed always).
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
    download_dataset_from_fire(file_in_fire, save_to=output_dir)

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


def test_error_is_thrown_if_directory_does_not_exist(file_in_fire):
    """
    The user wants to download a file into a specific, user-specified directory,
    but that directory does not exist. In this case, an error is thrown.
    """

    output_dir = 'user_specified_directory'

    expected_local_file_name = f'/{output_dir}/{FILE_ID}/{DISPLAY_FILE_NAME}'
    expected_local_md5_file_name = f'{expected_local_file_name}.md5'

    assert not os.path.exists(output_dir)
    assert not os.path.exists(expected_local_file_name)
    assert not os.path.exists(expected_local_md5_file_name)

    with pytest.raises(NotADirectoryError) as exception_info:
        download_dataset_from_fire(file_in_fire, save_to=output_dir)

    assert exception_info.value.args[0] == 'The "user_specified_directory" directory, which was specified by ' \
                                           'the --saveto command-line argument, is not an existing directory. ' \
                                           'Please either create that directory or specify a different one.'

    assert not os.path.exists(output_dir)
    assert not os.path.exists(expected_local_file_name)
    assert not os.path.exists(expected_local_md5_file_name)


def test_if_specified_dir_is_a_file_then_error_is_thrown(file_in_fire, fs):
    """
    The user wants to download a file into a specific, user-specified directory,
    but that directory is, in fact, a file. An error is thrown and nothing is downloaded.
    """

    output_dir = 'user_specified_directory'
    existing_file = output_dir

    fs.create_file(existing_file)
    assert os.path.exists(existing_file)
    assert os.path.isfile(existing_file)

    with pytest.raises(NotADirectoryError) as exception_info:
        download_dataset_from_fire(file_in_fire, save_to=output_dir)

    assert exception_info.value.args[0] == 'The "user_specified_directory" directory, which was specified by ' \
                                           'the --saveto command-line argument, is not an existing directory. ' \
                                           'Please either create that directory or specify a different one.'

    assert os.path.exists(existing_file)
    assert os.path.isfile(existing_file)


def test_non_existing_directory_is_created(file_in_fire):
    """
    The user wants to download a file into a specific, user-specified directory.
    The directory does not exist.
    Expected: the non-existent directory is created automatically for the user,
    the file is downloaded into the user-specified directory
    and the file-name will be the 'displayFileName' (e.g. 'EGAF00000000001/ENCFF284YOU.bam.bai').
    """

    output_dir = 'user_specified_directory'
    expected_local_file_name = f'/{output_dir}/{FILE_ID}/{DISPLAY_FILE_NAME}'
    expected_local_md5_file_name = f'{expected_local_file_name}.md5'

    assert not os.path.exists(output_dir)
    assert not os.path.exists(expected_local_file_name)
    assert not os.path.exists(expected_local_md5_file_name)

    download_dataset_from_fire(file_in_fire, output_dir=output_dir)

    assert os.path.isdir(output_dir)
    assert os.path.isfile(expected_local_file_name)
    assert os.path.isfile(expected_local_md5_file_name)
