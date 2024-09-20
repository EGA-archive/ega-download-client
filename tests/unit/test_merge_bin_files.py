import os
import random
import tempfile
from unittest import mock

from psutil import virtual_memory

from pyega3.libs import utils


@mock.patch('os.remove')
def test_merge_bin_files_on_disk(mocked_remove):
    mem = virtual_memory().available
    files_to_merge = {}

    # Create temporary files to simulate file merging
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create actual temporary files for 'f1.bin', 'f2.bin', and 'f3.bin'
        for i in range(1, 4):
            file_name = f'f{i}.bin'
            file_path = os.path.join(temp_dir, file_name)
            file_content = os.urandom(random.randint(1, mem // 512))
            files_to_merge[file_path] = file_content
            with open(file_path, 'wb') as f:
                f.write(file_content)

        # Create the target file (merged file)
        target_file_name = os.path.join(temp_dir, "merged.file")

        # Call the real merge function, using real temporary files
        utils.merge_bin_files_on_disk(target_file_name, list(files_to_merge.keys()), 0)

        # Read the contents of the merged file and verify
        with open(target_file_name, 'rb') as merged_file:
            merged_bytes = merged_file.read()

        # Ensure that os.remove was called to delete all files except the first one
        mocked_remove.assert_has_calls([mock.call(f) for f in list(files_to_merge.keys())[1:]])

        # Verify that the merged bytes match the content of all files in order
        verified_bytes = 0
        for file_path, f_content in files_to_merge.items():
            f_len = len(f_content)
            assert f_content == merged_bytes[verified_bytes:verified_bytes + f_len]
            verified_bytes += f_len

        assert verified_bytes == len(merged_bytes)
