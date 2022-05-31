import re

from tests.functional.conftest import PYEGA3_NAME, PYEGA3_VERSION


def test_install(install_package):
    exit_code, output, error = install_package
    assert exit_code == 0
    assert bool(re.search(f'Successfully installed {PYEGA3_NAME}-{PYEGA3_VERSION}', output))
