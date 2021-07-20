import os

from pyega3.libs.data_file import DataFile


def test_in_some_folder(mock_data_client):
    folder = "FOO"
    file_id = "EGAF001"
    base_name = "filename"
    base_ext = ".ext"
    full_name = "/really/long/" + base_name + base_ext
    file = DataFile(mock_data_client, file_id, display_file_name=full_name)
    assert (
            file.generate_output_filename(folder, None)
            == os.path.join(folder, file_id, base_name + base_ext)
    )


def test_in_current_directory(mock_data_client):
    folder = os.getcwd()
    file_id = "EGAF001"
    base_name = "filename"
    base_ext = ".ext"
    full_name = "/really/long/" + base_name + base_ext
    file = DataFile(mock_data_client, file_id, display_file_name=full_name)
    assert (
            file.generate_output_filename(folder, None)
            == os.path.join(folder, file_id, base_name + base_ext)
    )


def test_with_genomic_range(mock_data_client):
    folder = os.getcwd()
    file_id = "EGAF001"
    base_name = "filename"
    base_ext = ".ext"
    full_name = "/really/long/" + base_name + base_ext
    file = DataFile(mock_data_client, file_id, display_file_name=full_name)
    assert (
            file.generate_output_filename(folder, ("chr1", None, 100, 200, "CRAM"))
            == os.path.join(folder, file_id, base_name + "_genomic_range_chr1_100_200" + base_ext + ".cram")
    )
