import pytest

import pyega3.pyega3 as pyega3


# FIXME bjuhasz, afoix
@pytest.mark.skip(reason="temporarily skipping this")
def test_main_exits():
    with pytest.raises(SystemExit):
        pyega3.main()
