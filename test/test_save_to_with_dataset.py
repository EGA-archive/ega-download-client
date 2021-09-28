import os

import pytest

from pyega3.libs import utils
from pyega3.libs.data_set import DataSet

FILE_ID = 'EGAF00000000001'
DISPLAY_FILE_NAME = 'ENCFF284YOU.bam.bai'
SAVE_TO_FILE_NAME = 'FileNameGivenByTheUser.bumm.bamm'


# @pytest.fixture()
# def file_in_fire(mock_data_server, mock_data_client, random_binary_file, fs):
#     mock_data_server.file_content[FILE_ID] = random_binary_file
#     file_md5 = hashlib.md5(random_binary_file).hexdigest()
#     yield DataFile(mock_data_client, FILE_ID, display_file_name=DISPLAY_FILE_NAME,
#                    file_name=DISPLAY_FILE_NAME + '.cip', size=len(random_binary_file) + 16,
#                    unencrypted_checksum=file_md5)


@pytest.fixture()
def dataset_in_fire(mock_data_client, dataset_with_files):
    yield DataSet(mock_data_client, dataset_with_files.id)


def download_dataset_from_fire(dataset_in_fire, save_to):
    dataset_in_fire.download(num_connections=1, output_dir=save_to, genomic_range_args=None,
                             max_retries=5, retry_wait=0)


class TestWhenSaveToIsSpecified:
    """
    These tests test those DataFile.download_file_retry() invocations,
    when the user supplied a 'save_to' parameter by the '--saveto' command-line parameter.
    """

    def test_file_is_saved_into_an_existing_directory_which_was_specified_by_the_user(self, dataset_in_fire, fs):
        """
        The user wants to download a file into a specific, user-specified directory.
        The directory exists and there is no such file in that directory yet.
        Expected: the file is downloaded into the user-specified directory
        and the file-name will be the 'displayFileName' (e.g. 'EGAF00000000001/ENCFF284YOU.bam.bai').
        """

        save_to_dir_name = 'user_specified_directory'
        os.makedirs(save_to_dir_name)

        expected_local_file_name = f'/{save_to_dir_name}/{FILE_ID}/{DISPLAY_FILE_NAME}'
        expected_local_md5_file_name = f'{expected_local_file_name}.md5'

        assert os.path.isdir(save_to_dir_name)
        assert not os.path.exists(expected_local_file_name)
        assert not os.path.exists(expected_local_md5_file_name)

        download_dataset_from_fire(dataset_in_fire, save_to=save_to_dir_name)

        assert os.path.isfile(expected_local_file_name)
        assert os.path.isfile(expected_local_md5_file_name)

    def test_file_in_directory_is_not_downloaded_again(self, file_in_fire, random_binary_file, fs):
        """
        When the file has correctly been downloaded already into the specified directory,
        then it is not downloaded again.
        """

        save_to_dir_name = 'user_specified_directory_name'
        expected_local_file_name = f'/{save_to_dir_name}/{FILE_ID}/{DISPLAY_FILE_NAME}'
        expected_local_md5_file_name = f'{expected_local_file_name}.md5'

        # First I create the downloaded files to simulate a previous, successful download:
        fs.create_file(expected_local_file_name)
        fs.create_file(expected_local_md5_file_name)
        assert os.path.isdir(save_to_dir_name)

        with open(expected_local_file_name, 'wb') as fh:
            fh.write(random_binary_file)
        with open(expected_local_md5_file_name, 'w') as fh:
            fh.write(file_in_fire.unencrypted_checksum)
        # And I store their original mtimes:
        local_file_orig_mtime = os.stat(expected_local_file_name).st_mtime
        local_md5_file_orig_mtime = os.stat(expected_local_md5_file_name).st_mtime

        # The downloaded files should exist:
        assert os.path.isdir(save_to_dir_name)
        assert os.path.isfile(expected_local_file_name)
        assert os.path.isfile(expected_local_md5_file_name)

        # Let's simulate a second download into the specified directory.
        # This should not download again the files,
        # but it should print out a "Local file exists" message.
        download_dataset_from_fire(file_in_fire, save_to=save_to_dir_name)

        local_file_mtime_after_download = os.stat(expected_local_file_name).st_mtime
        local_md5_file_mtime_after_download = os.stat(expected_local_md5_file_name).st_mtime

        # If the files haven't been re-downloaded again, then the mtimes should not have changed:
        assert local_file_orig_mtime == local_file_mtime_after_download
        assert local_md5_file_orig_mtime == local_md5_file_mtime_after_download

    def test_corrupted_file_in_a_directory_is_downloaded_again(self, file_in_fire, fs):
        """
        When the file has been downloaded incorrectly into a directory previously, then it is re-downloaded again.
        I don't think this happens too often, because an incorrectly downloaded file is always removed
        (or at least, it should be removed always).
        """

        save_to_dir_name = 'user_specified_directory_name'
        expected_local_file_name = f'/{save_to_dir_name}/{FILE_ID}/{DISPLAY_FILE_NAME}'
        expected_local_md5_file_name = f'{expected_local_file_name}.md5'

        # First I create a file to simulate a previous, unsuccessful download:
        fs.create_file(expected_local_file_name)
        with open(expected_local_file_name, 'w') as fh:
            fh.write('incorrect, corrupted content')

        # The downloaded file should exist, but without an .md5:
        assert os.path.isfile(expected_local_file_name)
        assert not os.path.exists(expected_local_md5_file_name)
        assert os.path.isdir(save_to_dir_name)

        # Let's simulate a second download into the specified directory.
        # This should download again the file and the .md5, this time, correctly.
        download_dataset_from_fire(file_in_fire, save_to=save_to_dir_name)

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

    def test_error_is_thrown_if_directory_does_not_exist(self, file_in_fire):
        """
        The user wants to download a file into a specific, user-specified directory,
        but that directory does not exist. In this case, an error is thrown.
        """

        save_to_dir_name = 'user_specified_directory'

        expected_local_file_name = f'/{save_to_dir_name}/{FILE_ID}/{DISPLAY_FILE_NAME}'
        expected_local_md5_file_name = f'{expected_local_file_name}.md5'

        assert not os.path.exists(save_to_dir_name)
        assert not os.path.exists(expected_local_file_name)
        assert not os.path.exists(expected_local_md5_file_name)

        with pytest.raises(NotADirectoryError) as exception_info:
            download_dataset_from_fire(file_in_fire, save_to=save_to_dir_name)

        assert exception_info.value.args[0] == 'The "user_specified_directory" directory, which was specified by ' \
                                               'the --saveto command-line argument, is not an existing directory. ' \
                                               'Please either create that directory or specify a different one.'

        assert not os.path.exists(save_to_dir_name)
        assert not os.path.exists(expected_local_file_name)
        assert not os.path.exists(expected_local_md5_file_name)

    def test_if_specified_dir_is_a_file_then_error_is_thrown(self, file_in_fire, fs):
        """
        The user wants to download a file into a specific, user-specified directory,
        but that directory is, in fact, a file. An error is thrown and nothing is downloaded.
        """

        save_to_dir_name = 'user_specified_directory'
        existing_file = save_to_dir_name

        fs.create_file(existing_file)
        assert os.path.exists(existing_file)
        assert os.path.isfile(existing_file)

        with pytest.raises(NotADirectoryError) as exception_info:
            download_dataset_from_fire(file_in_fire, save_to=save_to_dir_name)

        assert exception_info.value.args[0] == 'The "user_specified_directory" directory, which was specified by ' \
                                               'the --saveto command-line argument, is not an existing directory. ' \
                                               'Please either create that directory or specify a different one.'

        assert os.path.exists(existing_file)
        assert os.path.isfile(existing_file)


class TestWhenSaveToIsNotSpecified:
    """
    These tests test those DataFile.download_file_retry() invocations,
    when the user did not supply a 'save_to' parameter. This happens,
    when the user does not supply a '--saveto' parameter on the command-line.
    """

    # I cannot use __init__ to set up instance variables, because pytest skips
    # all classes which have a constructor: https://stackoverflow.com/a/21431187
    # So I simulate __init__ with a fixture which runs before each test.
    @pytest.fixture(autouse=True)
    def set_up_instance_variables(self):
        self.expected_local_file_name = f'/{FILE_ID}/{DISPLAY_FILE_NAME}'
        self.expected_local_md5_file_name = f'{self.expected_local_file_name}.md5'

    def test_file_is_saved_as_display_file_name(self, file_in_fire):
        """
        The user wants to download a file and there is no file
        (with 'displayFileName' as file-name) on the file-system yet.
        Expected: the file is downloaded as 'displayFileName' (e.g. 'EGAF00000000001/ENCFF284YOU.bam.bai').
        """

        assert not os.path.exists(self.expected_local_file_name)
        assert not os.path.exists(self.expected_local_md5_file_name)

        download_dataset_from_fire(file_in_fire, save_to=None)

        assert os.path.isfile(self.expected_local_file_name)
        assert os.path.isfile(self.expected_local_md5_file_name)

    def test_file_is_not_downloaded_again(self, file_in_fire, random_binary_file, fs):
        """When the file has correctly been downloaded already, then it is not downloaded again."""

        # First I create the downloaded files to simulate a previous, successful download:
        fs.create_file(self.expected_local_file_name)
        fs.create_file(self.expected_local_md5_file_name)

        with open(self.expected_local_file_name, 'wb') as fh:
            fh.write(random_binary_file)
        with open(self.expected_local_md5_file_name, 'w') as fh:
            fh.write(file_in_fire.unencrypted_checksum)
        # And I store their original mtimes:
        local_file_orig_mtime = os.stat(self.expected_local_file_name).st_mtime
        local_md5_file_orig_mtime = os.stat(self.expected_local_md5_file_name).st_mtime

        # The downloaded files should exist:
        assert os.path.isfile(self.expected_local_file_name)
        assert os.path.isfile(self.expected_local_md5_file_name)

        # Let's simulate a second download. This should not download again the files,
        # but it should print out a "Local file exists" message.
        download_dataset_from_fire(file_in_fire, save_to=None)

        local_file_mtime_after_download = os.stat(self.expected_local_file_name).st_mtime
        local_md5_file_mtime_after_download = os.stat(self.expected_local_md5_file_name).st_mtime

        # If the files haven't been re-downloaded again, then the mtimes should not have changed:
        assert local_file_orig_mtime == local_file_mtime_after_download
        assert local_md5_file_orig_mtime == local_md5_file_mtime_after_download

    def test_corrupted_file_is_downloaded_again(self, file_in_fire, fs):
        """
        When the file has not been downloaded correctly previously, then it is downloaded again.
        I don't think this happens too often, because an incorrectly downloaded file is always removed
        (or at least, it should be removed always).
        """

        # First I create a file to simulate a previous, unsuccessful download:
        fs.create_file(self.expected_local_file_name)
        with open(self.expected_local_file_name, 'w') as fh:
            fh.write('incorrect, corrupted content')

        # The downloaded file should exist, but without an .md5:
        assert os.path.isfile(self.expected_local_file_name)
        assert not os.path.exists(self.expected_local_md5_file_name)

        # Let's simulate a second download. This should download again the file and the .md5, this time, correctly.
        download_dataset_from_fire(file_in_fire, save_to=None)

        # Check that the actual MD5 of the re-downloaded file is correct:
        correct_expected_md5 = file_in_fire.unencrypted_checksum
        actual_md5 = utils.calculate_md5(self.expected_local_file_name, file_in_fire.size)
        assert actual_md5 == correct_expected_md5

        # The .md5 file should now exist:
        assert os.path.isfile(self.expected_local_md5_file_name)

        # And the content of the .md5 file should be the correct, expected one:
        with open(self.expected_local_md5_file_name, 'r') as fh:
            actual_md5 = fh.readline()
        assert actual_md5 == correct_expected_md5
