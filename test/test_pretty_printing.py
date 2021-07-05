import pyega3.pyega3 as pyega3


def test_pretty_print_authorized_datasets():
    pyega3.pretty_print_authorized_datasets(['EGAD0123'])


def test_pretty_print_files_in_dataset():
    test_reply = [{"checksumType": "MD5", "unencryptedChecksum": "MD5SUM678901234567890123456789012",
                   "fileName": "EGAZ00001314035.bam.bai.cip", "displayFileName": "EGAZ00001314035.bam.bai.cip",
                   "fileStatus": "available",
                   "fileSize": 0, "datasetId": "EGAD00001003338", "fileId": "EGAF00001753747"}]
    pyega3.pretty_print_files_in_dataset(test_reply)
