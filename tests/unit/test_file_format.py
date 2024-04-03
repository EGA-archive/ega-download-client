from unittest.mock import patch

import pytest
from pyega3.libs.file_format import autocorrect_format_in_genomic_range_args, is_bam_or_cram_file


@pytest.fixture
def mock_warning():
    with patch('logging.warning') as mock_warning:
        yield mock_warning


def test_format_matches_detected(mock_warning):
    name = "example.bam.cip"
    genomic_range_args = ("chr1", 100, 200, "reference", "BAM")
    format_list = ["BAM", "CRAM"]

    result = autocorrect_format_in_genomic_range_args(name, genomic_range_args, format_list)

    assert result == genomic_range_args
    mock_warning.assert_not_called()


def test_format_does_not_match_detected(mock_warning):
    name = "example.cram.cip"
    genomic_range_args = ("chr1", 100, 200, "reference", "BAM")
    format_list = ["BAM", "CRAM"]

    result = autocorrect_format_in_genomic_range_args(name, genomic_range_args, format_list)

    expected_result = ("chr1", 100, 200, "reference", "CRAM")
    assert result == expected_result
    mock_warning.assert_called_once_with("Warning: The specified format BAM does not match the detected format in "
                                         "the file name, example.cram.cip , detected format: CRAM. The detected "
                                         "format will be used since transcoding is not yet supported by the file "
                                         "distribution service.")


def test_no_format_specified_and_not_detected(mock_warning):
    name = "example.unknown.cip"
    genomic_range_args = ("chr1", 100, 200, "reference", None)
    format_list = ["BAM", "CRAM"]

    result = autocorrect_format_in_genomic_range_args(name, genomic_range_args, format_list)

    assert result == genomic_range_args
    mock_warning.assert_called_once_with(
        "Warning: No file format was specified nor detected. The file distribution service will use 'BAM' as the "
        "default format. If you require a different format, please specify it using the '--format' option,"
        "followed by the desired format (e.g., '--format CRAM'). For a list of supported formats, "
        "use the '--help' option.")


def test_no_format_specified_but_detected(mock_warning):
    name = "example.cram.cip"
    genomic_range_args = ("chr1", 100, 200, "reference", None)
    format_list = ["BAM", "CRAM"]

    result = autocorrect_format_in_genomic_range_args(name, genomic_range_args, format_list)

    expected_result = ("chr1", 100, 200, "reference", "CRAM")
    assert result == expected_result
    mock_warning.assert_not_called()


def test_is_bam_or_cram_file_returns_true():
    name = "example.bam"
    assert is_bam_or_cram_file(name)

    name = "example.cram"
    assert is_bam_or_cram_file(name)

    name = "example.cram.cip"
    assert is_bam_or_cram_file(name)

    name = "example.2.bam.cip"
    assert is_bam_or_cram_file(name)

    name = "example.bam.cip"
    assert is_bam_or_cram_file(name)


def test_is_bam_or_cram_file_returns_false():
    name = "example.vcf.cip"
    assert not is_bam_or_cram_file(name)

    name = "example.txt"
    assert not is_bam_or_cram_file(name)
