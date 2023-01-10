import os
import re
import shutil

from tests.functional.util import run

script_dir = os.path.dirname(__file__)


def test_download_file():
    file_id = 'EGAF00001753741'
    download_dir = f'{script_dir}/{file_id}'

    run_command_and_assert_download_complete(f'pyega3 -t fetch {file_id} --output-dir {script_dir}')
    _assert_complete_files(download_dir)
    cleanup(download_dir)


def test_multipart_downloading():
    file_id = 'EGAF00005001625'  # less 200MB, will create 2 slices
    conns = 2  # only 2 will be utilised
    download_dir = f'{script_dir}/{file_id}'

    run_command_and_assert_download_complete(f'pyega3 -t -c {conns} fetch {file_id} --output-dir {script_dir}')
    _assert_complete_files(download_dir)
    cleanup(download_dir)


def test_download_dataset():
    dataset = 'EGAD00001009826'
    download_dir = f'{script_dir}/{dataset}'
    os.makedirs(download_dir, exist_ok=True)
    run_command_and_assert_download_complete(f'pyega3 -t fetch {dataset} --output-dir {dataset}')
    _assert_all_files_downloaded(download_dir)
    cleanup(download_dir)


def _assert_all_files_downloaded(download_dir):
    file_dirs = [d for d in os.listdir(download_dir) if os.path.isdir(f'{download_dir}/{d}')]
    for d in file_dirs:
        _assert_complete_files(f'{download_dir}/{d}')


def run_command_and_assert_download_complete(command: str):
    exit_code, output, error = run(command)
    assert exit_code == 0
    output += error  # it seems that output is in stderr
    assert bool(re.search(f'Download complete', output))


def _assert_complete_files(file_dir):
    # there will be 2 files (the actual file and its md5 file)
    downloaded_files = [f for f in os.listdir(file_dir) if os.path.isfile(f'{file_dir}/{f}')]
    assert len(downloaded_files) == 2


def cleanup(download_dir):
    shutil.rmtree(download_dir)
    os.remove('pyega3_output.log')
