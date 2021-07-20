import os

import pytest

from pyega3.libs import utils


@pytest.mark.parametrize("md5,data", [
    ("d41d8cd98f00b204e9800998ecf8427e", b""),
    ("0cc175b9c0f1b6a831c399e269772661", b"a"),
    ("900150983cd24fb0d6963f7d28e17f72", b"abc"),
    ("f96b697d7cb7938d525a2f31aaf161d0", b"message digest"),
    ("c3fcd3d76192e4007dfb496cca67e13b", b"abcdefghijklmnopqrstuvwxyz"),
    ("d174ab98d277d9f5a5611c2c9f419d9f", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
    ("57edf4a22be3c955ac49da2e2107b67a",
     b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")
])
def test_md5(md5, data, mock_input_file):
    with mock_input_file(data) as input_file:
        assert utils.md5(input_file, len(data)) == md5


def test_calculating_md5_of_non_existent_file_raises_exception():
    non_existent_file = '/tmp/non/existent/file'
    assert not os.path.exists(non_existent_file)

    with pytest.raises(Exception):
        utils.calculate_md5(non_existent_file, -1)
