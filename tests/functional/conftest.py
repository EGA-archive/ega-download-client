import os

import pytest

from tests.functional.util import run

PYEGA3_NAME = os.environ.get('PYEGA3_NAME', 'pyega3')
PYEGA3_VERSION = os.environ.get('PYEGA3_VERSION', '4.0.3')

project_dir = os.path.dirname(__file__) + "../../../"

PYEGA3_DIST_DIR = os.environ.get('PYEGA3_DIST_DIR', f'{project_dir}/dist/{PYEGA3_NAME}-{PYEGA3_VERSION}.tar.gz')


@pytest.fixture(scope="session", autouse=True)
def install_package():
    return run(f'pip install {PYEGA3_DIST_DIR}')
