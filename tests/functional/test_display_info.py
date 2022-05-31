from tests.functional.conftest import PYEGA3_NAME
from tests.functional.util import run


def test_list_datasets():
    exit_code, output, error = run(f'{PYEGA3_NAME} -t datasets')
    assert exit_code == 0


def test_list_files():
    dataset = 'EGAD00001003338'
    exit_code, output, error = run(f'{PYEGA3_NAME} -t files {dataset}')
    assert exit_code == 0
