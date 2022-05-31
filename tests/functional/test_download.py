import os
import re
import shutil

from tests.functional.util import run

script_dir = os.path.dirname(__file__)


def test_download_file():
    file = 'EGAF00001753741'
    download_dir = f'{script_dir}/{file}'

    _assert_successful_run(f'pyega3 -t fetch {file} --output-dir {script_dir}', download_dir)
    _assert_complete_files(download_dir)
    _cleanup(download_dir)


def test_multipart_downloading():
    file = 'EGAF00005001625'  # less 200MB, will create 2 slices
    conns = 2  # only 2 will be utilised
    download_dir = f'{script_dir}/{file}'

    _assert_successful_run(f'pyega3 -t -c {conns} fetch {file} --output-dir {script_dir}', download_dir)
    _assert_complete_files(download_dir)
    _cleanup(download_dir)


def _assert_successful_run(command: str, download_dir: str):
    exit_code, output, error = run(command)
    assert exit_code == 0
    output += error  # it seems that output is in stderr
    assert bool(re.search(f'Download complete', output))


def _assert_complete_files(download_dir):
    downloaded_files = [f for f in os.listdir(download_dir) if os.path.isfile(f'{download_dir}/{f}')]
    assert len(downloaded_files) == 2


def _cleanup(download_dir):
    shutil.rmtree(download_dir)
    os.remove('pyega3_output.log')
