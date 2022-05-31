import logging
import os

import pytest

from pyega3.libs import utils
from pyega3.libs.data_set import DataSet

OUTPUT_DIR = 'user_specified_directory'


def file_and_md5_file_paths(mock_dataset_file):
    return [
        f'/{OUTPUT_DIR}/{mock_dataset_file["fileId"]}/{mock_dataset_file["displayFileName"]}',
        f'/{OUTPUT_DIR}/{mock_dataset_file["fileId"]}/{mock_dataset_file["displayFileName"]}.md5'
    ]


@pytest.fixture()
def expected_file_paths(mock_dataset_files):
    nested_paths = [file_and_md5_file_paths(file) for file in mock_dataset_files]

    def flatten(nested_list):
        return [element for sublist in nested_list for element in sublist]

    return flatten(nested_paths)


@pytest.fixture()
def dataset_in_fire(mock_data_client, dataset_with_files):
    return DataSet(mock_data_client, dataset_with_files.id)


def download_dataset_from_fire(dataset_in_fire):
    # num_connections, output_dir, genomic_range_args, max_retries=5, retry_wait=5
    dataset_in_fire.download(1, OUTPUT_DIR, None, max_retries=2, retry_wait=0)


def assert_that_expected_file_paths_not_exist(expected_file_paths):
    for path in expected_file_paths:
        assert not os.path.exists(path)


def assert_that_expected_file_paths_exist(expected_file_paths):
    for path in expected_file_paths:
        assert os.path.isfile(path)


def test_file_is_saved_into_an_existing_directory_which_was_specified_by_the_user(dataset_in_fire,
                                                                                  expected_file_paths,
                                                                                  fs):
    """
    The user wants to download a file into a specific, user-specified directory.
    The directory exists and there is no such file in that directory yet.
    Expected: the file is downloaded into the user-specified directory
    and the file-name will be the 'displayFileName' (e.g. 'EGAF00000000001/ENCFF284YOU.bam.bai').
    """

    os.makedirs(OUTPUT_DIR)

    assert os.path.isdir(OUTPUT_DIR)
    assert_that_expected_file_paths_not_exist(expected_file_paths)

    download_dataset_from_fire(dataset_in_fire)

    assert_that_expected_file_paths_exist(expected_file_paths)


def test_file_in_directory_is_not_downloaded_again(mock_dataset_files, dataset_in_fire, fs, caplog):
    """
    When the file has correctly been downloaded already into the specified directory,
    then it is not downloaded again.
    """
    caplog.set_level(logging.INFO)
    mtimes = {}

    # First I create the downloaded files to simulate a previous, successful download:
    for file in mock_dataset_files:
        file_path, md5_file_path = file_and_md5_file_paths(file)
        fs.create_file(file_path)

        with open(file_path, 'wb') as fh:
            fh.write(file['fileContent'])
        with open(md5_file_path, 'w') as fh:
            fh.write(file['unencryptedChecksum'])

        # And I store their original mtimes:
        mtimes[file_path] = os.stat(file_path).st_mtime
        mtimes[md5_file_path] = os.stat(md5_file_path).st_mtime

        # The downloaded files should exist:
        assert os.path.isfile(file_path)
        assert os.path.isfile(md5_file_path)

    assert os.path.isdir(OUTPUT_DIR)

    # Let's simulate a second download into the specified directory.
    # This should not download again the files,
    # but it should print out a "Local file exists" message.
    download_dataset_from_fire(dataset_in_fire)

    for file_path, orig_mtime_before_second_download in mtimes.items():
        mtime_after_second_download = os.stat(file_path).st_mtime
        # If the files haven't been re-downloaded again, then the mtimes should not have changed:
        assert mtime_after_second_download == orig_mtime_before_second_download

        if not file_path.endswith('.md5'):
            assert f"Local file exists:'{file_path}'" in caplog.text


def test_corrupted_file_in_a_directory_is_downloaded_again(mock_dataset_files, dataset_in_fire, fs):
    """
    When the file has been downloaded incorrectly into a directory previously, then it is re-downloaded again.
    I don't think this happens too often, because an incorrectly downloaded file is always removed
    (or at least, it should be removed always).
    """
    # First I create the downloaded files to simulate a previous, successful download:
    for file in mock_dataset_files:
        file_path, md5_file_path = file_and_md5_file_paths(file)

        # First I create a file to simulate a previous, unsuccessful download:
        fs.create_file(file_path)
        with open(file_path, 'w') as fh:
            fh.write('incorrect, corrupted content')

        # The downloaded file should exist, but without an .md5:
        assert os.path.isfile(file_path)
        assert not os.path.exists(md5_file_path)

    assert os.path.isdir(OUTPUT_DIR)

    # Let's simulate a second download into the specified directory.
    # This should download again the file and the .md5, this time, correctly.
    download_dataset_from_fire(dataset_in_fire)

    for file in mock_dataset_files:
        file_path, md5_file_path = file_and_md5_file_paths(file)

        # Check that the actual MD5 of the re-downloaded file is correct:
        correct_expected_md5 = file['unencryptedChecksum']
        actual_md5 = utils.calculate_md5(file_path, file['fileSize'])
        assert actual_md5 == correct_expected_md5

        # The .md5 file should now exist:
        assert os.path.isfile(md5_file_path)

        # And the content of the .md5 file should be the correct, expected one:
        with open(md5_file_path, 'r') as fh:
            actual_md5 = fh.readline()
        assert actual_md5 == correct_expected_md5


def test_if_specified_dir_is_a_file_then_error_is_thrown(dataset_in_fire, expected_file_paths, caplog, fs):
    """
    The user wants to download a file into a specific, user-specified directory,
    but that directory is, in fact, a file. An error is thrown and nothing is downloaded.
    """
    caplog.set_level(logging.INFO)

    existing_file = OUTPUT_DIR
    fs.create_file(existing_file)
    assert os.path.exists(existing_file)
    assert os.path.isfile(existing_file)

    assert_that_expected_file_paths_not_exist(expected_file_paths)

    download_dataset_from_fire(dataset_in_fire)

    assert f"Not a directory in the fake filesystem: '/{OUTPUT_DIR}'" in caplog.text

    assert_that_expected_file_paths_not_exist(expected_file_paths)


def test_non_existing_directory_is_created(dataset_in_fire, expected_file_paths, fs):
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

    assert not os.path.exists(OUTPUT_DIR)
    assert_that_expected_file_paths_not_exist(expected_file_paths)

    download_dataset_from_fire(dataset_in_fire)

    assert_that_expected_file_paths_exist(expected_file_paths)
