from pyega3.libs.data_file import DataFile
from pyega3.libs.data_set import DataSet
from pyega3.libs.pretty_printing import *


def test_pretty_print_authorized_datasets(mock_data_client):
    pretty_print_authorized_datasets([DataSet(mock_data_client, 'EGAD0123')])


def test_pretty_print_files_in_dataset(mock_data_client):
    test_reply = [DataFile(mock_data_client, "EGAF00001753747",
                           display_file_name="EGAZ00001314035.bam.bai.cip",
                           file_name="EGAZ00001314035.bam.bai.cip",
                           size=0,
                           unencrypted_checksum="MD5SUM678901234567890123456789012",
                           status="available")]
    pretty_print_files_in_dataset(test_reply)
