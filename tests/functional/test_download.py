import os
import re
import shutil

from tests.functional.util import run


def test_download_file():
    file = 'EGAF00001753741'

    parent_dir = os.path.dirname(__file__)
    download_dir = f'{parent_dir}/{file}'

    exit_code, output, error = run(f'pyega3 -t fetch {file} --output-dir {parent_dir}')

    assert exit_code == 0
    output += error  # it seems that output is in stderr

    assert bool(re.search(f'Download complete', output))

    downloaded_files = [f for f in os.listdir(download_dir) if os.path.isfile(f'{download_dir}/{f}')]
    assert len(downloaded_files) == 2

    shutil.rmtree(download_dir)
    os.remove('pyega3_output.log')
