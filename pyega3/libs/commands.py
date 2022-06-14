import logging
import logging.handlers
import sys

from requests.exceptions import HTTPError

from pyega3.libs import data_file
from pyega3.libs.data_set import DataSet
from pyega3.libs.pretty_printing import pretty_print_authorized_datasets, pretty_print_files_in_dataset
from pyega3.libs.utils import verify_output_dir


def execute_subcommand(args, data_client):
    try:
        if args.subcommand == "datasets":
            list_datasets(args, data_client)

        if args.subcommand == "files":
            list_files_in_dataset(args, data_client)

        elif args.subcommand == "fetch":
            fetch_data(args, data_client)
    except HTTPError as error:
        if error.response.status_code >= 500:
            logging.error("Could not communicate with the EGA repository because of an error on the server.\n"
                          "Please retry later, or contact helpdesk@ega-archive.org for assistance.\n"
                          f"(error detail: {error})")
        elif error.response.status_code == 429:
            logging.error("The EGA repository refused your request because you have made too many requests.\n"
                          "Please wait before making further requests. If you are running pyega3 in a script, please "
                          "add delays between your calls.")
        else:
            logging.error(f"There was a problem communicating with the EGA repository: {error}")


def fetch_data(args, data_client):
    output_dir = verify_output_dir(args.output_dir)
    genomic_range_args = (args.reference_name, args.reference_md5, args.start, args.end, args.format)
    if args.delete_temp_files:
        data_file.DataFile.temporary_files_should_be_deleted = True
    if args.identifier[3] == 'D':
        dataset = DataSet(data_client, args.identifier)
        dataset.download(args.connections, output_dir, genomic_range_args,
                         args.max_retries, args.retry_wait, args.max_slice_size)
    elif args.identifier[3] == 'F':
        file = data_file.DataFile(data_client, args.identifier)
        file.download_file_retry(num_connections=args.connections,
                                 output_dir=output_dir,
                                 genomic_range_args=genomic_range_args,
                                 max_retries=args.max_retries,
                                 retry_wait=args.retry_wait,
                                 max_slice_size=args.max_slice_size)
    else:
        logging.error(
            "Unrecognized identifier - please use EGAD accession for dataset request"
            " or EGAF accession for individual file requests")
        sys.exit()
    logging.info("Download complete")


def list_files_in_dataset(args, data_client):
    if args.identifier[3] != 'D':
        logging.error("Unrecognized identifier - please use EGAD accession for dataset requests")
        sys.exit()
    dataset = DataSet(data_client, args.identifier)
    files = dataset.list_files()
    pretty_print_files_in_dataset(files, args.json)


def list_datasets(args, data_client):
    datasets = DataSet.list_authorized_datasets(data_client)
    pretty_print_authorized_datasets(datasets, args.json)
