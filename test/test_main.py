import pytest

import pyega3.pyega3 as pyega3


def test_main_exits():
    with pytest.raises(SystemExit):
        pyega3.main()
