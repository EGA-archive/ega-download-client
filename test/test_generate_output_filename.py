import os

import pyega3.pyega3 as pyega3


def test_in_some_folder():
    folder = "FOO"
    file_id = "EGAF001"
    base_name = "filename"
    base_ext = ".ext"
    full_name = "/really/long/" + base_name + base_ext
    assert (
            pyega3.generate_output_filename(folder, file_id, full_name, None)
            == os.path.join(folder, file_id, base_name + base_ext)
    )


def test_in_current_directory():
    folder = os.getcwd()
    file_id = "EGAF001"
    base_name = "filename"
    base_ext = ".ext"
    full_name = "/really/long/" + base_name + base_ext
    assert (
            pyega3.generate_output_filename(folder, file_id, full_name, None)
            == os.path.join(folder, file_id, base_name + base_ext)
    )


def test_with_genomic_range():
    folder = os.getcwd()
    file_id = "EGAF001"
    base_name = "filename"
    base_ext = ".ext"
    full_name = "/really/long/" + base_name + base_ext
    assert (
            pyega3.generate_output_filename(folder, file_id, full_name, ("chr1", None, 100, 200, "CRAM"))
            == os.path.join(folder, file_id, base_name + "_genomic_range_chr1_100_200" + base_ext + ".cram")
    )
