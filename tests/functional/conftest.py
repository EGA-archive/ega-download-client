import os

import pytest

from tests.functional.util import run

PYEGA3_NAME = os.environ.get('PYEGA3_NAME', 'pyega3')
PYEGA3_VERSION = os.environ['PYEGA3_VERSION']
PYEGA3_DIST_DIR = os.environ['PYEGA3_DIST_DIR']
PYEGA3_PKG = f'{PYEGA3_DIST_DIR}/{PYEGA3_NAME}-{PYEGA3_VERSION}.tar.gz'


@pytest.fixture(scope="session", autouse=True)
def install_package():
    return run(f'pip install {PYEGA3_PKG}')
