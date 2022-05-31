import json

from pyega3.libs.data_file import DataFile
from pyega3.libs.data_set import DataSet
from pyega3.libs.pretty_printing import *


def test_pretty_print_authorized_datasets(mock_data_client):
    pretty_print_authorized_datasets([DataSet(mock_data_client, 'EGAD0123')], False)


def test_pretty_print_authorized_datasets_in_json(mock_data_client, caplog):
    caplog.set_level(logging.INFO)
    pretty_print_authorized_datasets([DataSet(mock_data_client, 'EGAD0123')], True)
    assert len(caplog.messages) == 1
    assert json.loads(caplog.messages[0]) == [{"id": "EGAD0123"}]


def test_pretty_print_files_in_dataset(mock_data_client):
    test_reply = [DataFile(mock_data_client, "EGAF00001753747",
                           display_file_name="EGAZ00001314035.bam.bai.cip",
                           file_name="EGAZ00001314035.bam.bai.cip",
                           size=0,
                           unencrypted_checksum="MD5SUM678901234567890123456789012",
                           status="available")]
    pretty_print_files_in_dataset(test_reply, False)


def test_pretty_print_files_in_dataset_in_json(mock_data_client, caplog):
    caplog.set_level(logging.INFO)
    test_reply = [DataFile(mock_data_client, "EGAF00001753747",
                           display_file_name="EGAZ00001314035.bam.bai.cip",
                           file_name="EGAZ00001314035.bam.bai.cip",
                           size=0,
                           unencrypted_checksum="MD5SUM678901234567890123456789012",
                           status="available")]
    pretty_print_files_in_dataset(test_reply, True)

    assert len(caplog.messages) == 1

    output_object = json.loads(caplog.messages[0])
    assert len(output_object) == 1
    assert output_object[0]["id"] == test_reply[0].id
    assert output_object[0]["name"] == test_reply[0].display_name
    assert output_object[0]["bytes"] == test_reply[0].size
    assert output_object[0]["checksum"] == test_reply[0].unencrypted_checksum
    assert output_object[0]["status"] == test_reply[0].status
