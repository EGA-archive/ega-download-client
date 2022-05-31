from tests.functional.util import run


def test_list_datasets():
    exit_code, output, error = run(f'pyega3 -t datasets')
    assert exit_code == 0


def test_list_files():
    dataset = 'EGAD00001003338'
    exit_code, output, error = run(f'pyega3 -t files {dataset}')
    assert exit_code == 0
