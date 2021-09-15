import logging
import json

from pyega3.libs.utils import status_ok


def pretty_print_authorized_datasets(datasets, as_json):
    if as_json:
        logging.info(json.dumps([{"id": dataset.id for dataset in datasets}]))
    else:
        logging.info("Dataset ID")
        logging.info("-----------------")
        for dataset in datasets:
            logging.info(dataset.id)


def pretty_print_files_in_dataset(files, as_json):
    """
    Print a table of files in authorized dataset from api call api_list_files_in_dataset

        {
           "checksumType": "MD5",
            "unencryptedChecksum": "MD5SUM678901234567890123456789012",
            "fileName": "EGAZ00001314035/b37/NA12878.bam.bai.cip",
            "displayFileName": "NA12878.bam.bai.cip",
            "fileStatus": "available",
            "fileSize": 8949984,
            "datasetId": "EGAD00001003338",
            "fileId": "EGAF00001753747"
        }

    """

    if as_json:
        logging.info(json.dumps([{
            "id": file.id,
            "status": file.status,
            "bytes": file.size,
            "checksum": file.unencrypted_checksum,
            "name": file.display_name
        } for file in files]))
    else:
        format_string = "{:15} {:6} {:12} {:36} {}"

        logging.info(format_string.format("File ID", "Status", "Bytes", "Check sum", "File name"))
        for file in files:
            logging.info(format_string.format(file.id, status_ok(file.status), str(file.size),
                                              file.unencrypted_checksum, file.display_name))

        logging.info('-' * 80)
        logging.info("Total dataset size = %.2f GB " % (sum(file.size for file in files) / (1024 * 1024 * 1024.0)))
