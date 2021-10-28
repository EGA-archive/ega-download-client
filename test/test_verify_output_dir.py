import os

import pytest

from pyega3.libs.utils import verify_output_dir


def test_absolute_path_is_returned_if_directory_exists(fs):
    output_dir = 'user_specified_directory'
    os.makedirs(output_dir)

    assert os.path.exists(output_dir)
    assert os.path.isdir(output_dir)

    verified_output_dir = verify_output_dir(output_dir)

    absolute_path_of_output_dir = '/user_specified_directory'
    assert verified_output_dir == absolute_path_of_output_dir


def test_error_is_thrown_if_directory_does_not_exist(fs):
    """
    The user wants to download a file into a specific, user-specified directory,
    but that directory does not exist. In this case, an error is thrown.
    """

    output_dir = 'user_specified_directory'
    assert not os.path.exists(output_dir)

    with pytest.raises(NotADirectoryError) as exception_info:
        verify_output_dir(output_dir)

    assert exception_info.value.args[0] == 'The "user_specified_directory" directory, which was specified by ' \
                                           'the --output-dir command-line argument, is not an existing directory. ' \
                                           'Please either create that directory or specify a different one.'


def test_if_specified_dir_is_a_file_then_error_is_thrown(fs):
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
        verify_output_dir(existing_file)

    assert exception_info.value.args[0] == 'The "user_specified_directory" directory, which was specified by ' \
                                           'the --output-dir command-line argument, is not an existing directory. ' \
                                           'Please either create that directory or specify a different one.'

    assert os.path.exists(existing_file)
    assert os.path.isfile(existing_file)
