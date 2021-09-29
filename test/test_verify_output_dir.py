import responses


def test_when_ipinfo_is_blocked_return_unknown(mock_requests):
    endpoint = 'https://ipinfo.io/json'
    mock_requests.add(responses.GET, endpoint, status=403)

    resp_ip = get_client_ip()

    assert resp_ip == 'Unknown'


def test_error_is_thrown_if_directory_does_not_exist(self, file_in_fire):
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
        download_file_from_fire(file_in_fire, output_dir=output_dir)

    assert exception_info.value.args[0] == 'The "user_specified_directory" directory, which was specified by ' \
                                           'the --saveto command-line argument, is not an existing directory. ' \
                                           'Please either create that directory or specify a different one.'

    assert not os.path.exists(output_dir)
    assert not os.path.exists(expected_local_file_name)
    assert not os.path.exists(expected_local_md5_file_name)


def test_if_specified_dir_is_a_file_then_error_is_thrown(self, file_in_fire, fs):
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
        download_file_from_fire(file_in_fire, output_dir=output_dir)

    assert exception_info.value.args[0] == 'The "user_specified_directory" directory, which was specified by ' \
                                           'the --saveto command-line argument, is not an existing directory. ' \
                                           'Please either create that directory or specify a different one.'

    assert os.path.exists(existing_file)
    assert os.path.isfile(existing_file)
