import os
import random
from unittest import mock

from psutil import virtual_memory

from pyega3.libs import utils


@mock.patch('os.remove')
def test_merge_bin_files_on_disk(mocked_remove):
    mem = virtual_memory().available
    files_to_merge = {
        'f1.bin': os.urandom(random.randint(1, mem // 512)),
        'f2.bin': os.urandom(random.randint(1, mem // 512)),
        'f3.bin': os.urandom(random.randint(1, mem // 512)),
    }
    target_file_name = "merged.file"

    merged_bytes = bytearray()

    def mock_write(buf):
        merged_bytes.extend(buf)

    real_open = open

    def open_wrapper(filename, mode):
        if filename == target_file_name:
            file_object = mock.mock_open().return_value
            file_object.write.side_effect = mock_write
            return file_object
        if filename not in files_to_merge:
            return real_open(filename, mode)
        content = files_to_merge[filename]
        length = len(content)
        buf_size = 65536
        file_object = mock.mock_open(read_data=content).return_value
        file_object.__iter__.return_value = [content[i:min(i + buf_size, length)] for i in
                                             range(0, length, buf_size)]
        return file_object

    with mock.patch('builtins.open', new=open_wrapper):
        with mock.patch('os.rename', lambda s, d: merged_bytes.extend(files_to_merge[os.path.basename(s)])):
            utils.merge_bin_files_on_disk(target_file_name, list(files_to_merge.keys()),
                                          0)  # this value can be changed from 0 to other/actual value

    mocked_remove.assert_has_calls([mock.call(f) for f in list(files_to_merge.keys())[1:]])

    verified_bytes = 0
    for f_content in files_to_merge.values():
        f_len = len(f_content)
        assert f_content == merged_bytes[verified_bytes: verified_bytes + f_len]
        verified_bytes += f_len

    assert verified_bytes == len(merged_bytes)
