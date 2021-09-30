import logging
import sys

from pyega3.libs import data_file
from pyega3.libs.data_file import DataFile
from pyega3.libs.utils import status_ok

LEGACY_DATASETS = ["EGAD00000000003", "EGAD00000000004", "EGAD00000000005", "EGAD00000000006", "EGAD00000000007",
                   "EGAD00000000008", "EGAD00000000009", "EGAD00000000025", "EGAD00000000029", "EGAD00000000043",
                   "EGAD00000000048", "EGAD00000000049", "EGAD00000000051", "EGAD00000000052", "EGAD00000000053",
                   "EGAD00000000054", "EGAD00000000055", "EGAD00000000056", "EGAD00000000057", "EGAD00000000060",
                   "EGAD00000000114", "EGAD00000000119", "EGAD00000000120", "EGAD00000000121", "EGAD00000000122",
                   "EGAD00001000132", "EGAD00010000124", "EGAD00010000144", "EGAD00010000148", "EGAD00010000150",
                   "EGAD00010000158", "EGAD00010000160", "EGAD00010000162", "EGAD00010000164", "EGAD00010000246",
                   "EGAD00010000248", "EGAD00010000250", "EGAD00010000256", "EGAD00010000444"]


class DataSet:
    def __init__(self, data_client, dataset_id):
        self.id = dataset_id
        self.data_client = data_client

    @staticmethod
    def list_authorized_datasets(data_client):
        """List datasets to which the credentialed user has authorized access"""

        reply = data_client.get_json("/metadata/datasets")

        if reply is None:
            logging.error(
                "You do not currently have access to any datasets at EGA according to our databases."
                " If you believe you should have access please contact helpdesk on helpdesk@ega-archive.org")
            sys.exit()

        return [DataSet(data_client, dataset_id) for dataset_id in reply]

    def list_files(self):
        if self.id in LEGACY_DATASETS:
            logging.error(f"This is a legacy dataset {self.id}. Please contact the EGA helpdesk at "
                          f"helpdesk@ega-archive.org for more information.")
            sys.exit()

        authorized_datasets = DataSet.list_authorized_datasets(self.data_client)

        if self.id not in [dataset.id for dataset in authorized_datasets]:
            logging.error(f"Dataset '{self.id}' is not in the list of your authorized datasets.")
            sys.exit()

        reply = self.data_client.get_json(f"/metadata/datasets/{self.id}/files")

        if reply is None:
            logging.error(f"List files in dataset {self.id} failed")
            sys.exit()

        def make_data_file(res):
            display_file_name = res['displayFileName'] if 'displayFileName' in res else None
            file_name = res['fileName'] if 'fileName' in res else None
            size = res['fileSize'] if 'fileSize' in res else None
            unencrypted_checksum = res['unencryptedChecksum'] if 'unencryptedChecksum' in res else None
            return data_file.DataFile(self.data_client, res['fileId'],
                                      display_file_name=display_file_name,
                                      file_name=file_name,
                                      size=size,
                                      unencrypted_checksum=unencrypted_checksum,
                                      status=res['fileStatus'])

        return [make_data_file(res) for res in reply]

    def download(self, num_connections, output_dir, genomic_range_args, max_retries=5, retry_wait=5,
                 max_slice_size=DataFile.DEFAULT_SLICE_SIZE):
        if self.id in LEGACY_DATASETS:
            logging.error(
                f"This is a legacy dataset {self.id}. Please contact the EGA helpdesk at helpdesk@ega-archive.org for more information.")
            sys.exit()

        authorized_datasets = DataSet.list_authorized_datasets(self.data_client)

        if self.id not in [dataset.id for dataset in authorized_datasets]:
            logging.info(f"Dataset '{self.id}' is not in the list of your authorized datasets.")
            return

        files = self.list_files()
        for file in files:
            try:
                if status_ok(file.status):
                    file.download_file_retry(num_connections, output_dir, genomic_range_args, max_retries, retry_wait, max_slice_size)
            except Exception as e:
                logging.exception(e)
