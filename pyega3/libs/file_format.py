import logging
import re


def autocorrect_format_in_genomic_range_args(name: str, genomic_range_args: tuple, possible_format_list: list) -> tuple:
    file_format_from_user = genomic_range_args[4] if len(genomic_range_args) == 5 else None
    detected_file_format = detect_file_format(name, possible_format_list)
    if file_format_from_user and detected_file_format and file_format_from_user != detected_file_format:
        logging.warning(
            f"Warning: The specified format {file_format_from_user} does not match the detected format in the "
            f"file name, {name} , detected format: {detected_file_format}. The detected format will be used "
            f"since transcoding is not yet supported by the file distribution service.")

    if not file_format_from_user and not detected_file_format:
        logging.warning(
            "Warning: No file format was specified nor detected. The file distribution service will use 'BAM' as "
            "the default format. If you require a different format, please specify it using the '--format' option,"
            "followed by the desired format (e.g., '--format CRAM'). For a list of supported formats, "
            "use the '--help' option.")

    genomic_range_args_list = list(genomic_range_args)
    genomic_range_args_list[4] = detected_file_format if detected_file_format else file_format_from_user
    updated_genomic_range_args = tuple(genomic_range_args_list)
    return updated_genomic_range_args


def is_bam_or_cram_file(filename: str):
    return search_format_in_filename("bam", filename) or search_format_in_filename("cram", filename)


def search_format_in_filename(file_format: str, filename: str):
    return re.search(f"\.{file_format}", filename, re.IGNORECASE)


def detect_file_format(filename, possible_format_list):
    detected_file_format = None

    for file_format in possible_format_list:
        if search_format_in_filename(file_format.lower(), filename):
            detected_file_format = file_format
            break

    return detected_file_format
