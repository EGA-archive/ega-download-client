# EGA download client: pyEGA3

## Overview

The pyEGA3 download client is a python-based tool for viewing and downloading files from authorized EGA datasets. pyEGA3 uses the EGA Data API and has several key features:
* Files are transferred over secure https connections and received unencrypted, so no need for decryption after download.
* Downloads resume from where they left off in the event that the connection is interrupted.
* pyEGA3 supports file segmenting and parallelized download of segments, improving overall performance.
* After download completes, file integrity is verified using checksums.
* pyEGA3 implements the GA4GH-compliant htsget protocol for download of genomic ranges for data files with accompanying index files.

### Tutorial video

 A video tutorial demonstrating the usage of pyEGA3 from installation through file download is available [here](https://embl-ebi.cloud.panopto.eu/Panopto/Pages/Viewer.aspx?id=be79bb93-1737-4f95-b80f-ab4300aa6f5a).

## Requirements

* Python 3.6 or newer. ([download instructions](https://www.python.org/downloads/))

## Installation and update

### Using Pip3

1. Install pyEGA3 using pip3.

    ```bash
    sudo pip3 install pyega3
    ```

1. Update pyEGA3, if needed, using pip3.

    ```bash
    pip3 install pyega3 --upgrade
    ```

1. Test your pip3 installation by running pyEGA3.

    ```bash
    pyega3 --help
    ```

### Using conda (bioconda channel)

1. Install pyEGA3 using conda.

    ```bash
    conda config --add channels bioconda
    conda config --add channels conda-forge
    conda install pyega3
    ```

1. Update pyEGA3, if needed, using conda.

    ```bash
    conda update pyega3
    ```

1. Test your conda installation by running pyEGA3.

    ```bash
    pyega3 --help
    ```

### Using GitHub

1. Clone the [ega-download-client](https://github.com/EGA-archive/ega-download-client) GitHub repository.

1. Navigate to the directory where the repository was cloned.

    ```bash
    cd path/to/ega-download-client
    ```

1. Three scripts are provided to install the required Python environment depending on the host operating system.
    * Linux (Red Hat): red_hat_dependency_install.sh
    * Linux: debian_dependency_install.sh
    * macOS: osx_dependency_install.sh

1. Execute the script corresponding to the host operating system. For example, if using Red Hat Linux, run:

    ```bash
    sh red_hat_dependency_install.sh
    ```

1. Test your GitHub installation by running pyEGA3.

    ```bash
    python -m pyega3.pyega3 --help
    ```

### Using Docker

There are Docker images built by Bioconda: https://bioconda.github.io/recipes/pyega3/README.html
An example of running pyEGA3 in a Docker container:

```bash
docker run --rm -v /tmp:/app -w /app quay.io/biocontainers/pyega3:3.4.0--py_0 pyega3 -d -t fetch EGAF00001775036
```

This example command mounts your /tmp folder into the Docker container as /app,
starts the 3.4.0 version of pyEGA3 and downloads a test file.
The test file will be downloaded into your /tmp folder.
You can find other, possibly newer, versions ("tags") of the pyEGA3 Docker image
on the above-mentioned Bioconda page.

## Usage - File download

```bash
usage: pyega3.py [-h] [-d] [-cf CONFIG_FILE] [-sf SERVER_FILE] [-c CONNECTIONS] [-t] [-ms MAX_SLICE_SIZE] {datasets,files,fetch} ...

Download from EMBL EBI's EGA (European Genome-phenome Archive)

positional arguments:
  {datasets,files,fetch}
                        subcommands
    datasets            List authorized datasets
    files               List files in a specified dataset
    fetch               Fetch a dataset or file

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Extra debugging messages
  -cf CONFIG_FILE, --config-file CONFIG_FILE
                        JSON file containing credentials/config e.g.{"username":"user1","password":"toor"}
  -sf SERVER_FILE, --server-file SERVER_FILE
                        JSON file containing server config e.g.{"url_auth":"aai url","url_api":"api url", "url_api_ticket":"htsget url", "client_secret":"client secret"}
  -c CONNECTIONS, --connections CONNECTIONS
                        Download using specified number of connections (default: 1 connection)
  -t, --test            Test user activated
  -ms MAX_SLICE_SIZE, --max-slice-size MAX_SLICE_SIZE
                        Set maximum size for each slice in bytes (default: 100 MB)

```

### Testing pyEGA3 installation

We recommend that all fresh installations of pyEGA3 be tested. A test account has been created which can be used (`-t`) to test the following pyEGA3 actions:

#### List the datasets available to the test account

```bash
pyega3 -d -t datasets
```

#### List the files available in a test dataset

```bash
pyega3 -d -t files EGAD00001003338
```

#### Download a test file

```bash
pyega3 -d -t fetch EGAF00001775036
```

The test dataset (EGAD00001003338) is large (almost 1TB), so please be mindful if deciding to test downloading the entire dataset. The test account does not require an EGA username and password because it contains publicaly accessible files from the [1000 Genomes Project](https://www.internationalgenome.org/data). The files in the test dataset can be used for troubleshooting and training purposes.

### Defining credentials

To view and download files for which you have been granted access, pyEGA3 requires your EGA username (email address) and password saved to a credentials file.

Create a file called CREDENTIALS_FILE and place it in the directory where pyEGA3 will run. The credentials file must be in JSON format and must contain your registered EGA username (email address) and password provided by EGA Helpdesk.

An example CREDENTIALS_FILE is available [here](https://github.com/EGA-archive/ega-download-client/blob/master/pyega3/config/default_credential_file.json).

### Using pyEGA3 for file download

*Replace `<these values>` with values relevant for your datasets.*

#### Display authorized datasets

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> datasets
```

#### Display files in a dataset

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> files EGAD<NUM>
```

#### Download a dataset

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> fetch EGAD<NUM> --output-dir </Path/To/OutputDirectory>
```

#### Download a single file

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> fetch EGAF<NUM> --output-dir </Path/To/OutputDirectory>
```

#### List unencrypted md5 checksums for all files in a dataset

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> files EGAD<NUM>
```

#### Save unencrypted md5 checksums to a file

```bash
nohup pyega3 -cf </Path/To/CREDENTIALS_FILE> files EGAD<NUM> </Path/To/File/md5sums.txt>
```

#### Download a file or dataset using 5 connections

```bash
pyega3 -c 5 -cf </Path/To/CREDENTIALS_FILE> fetch EGAD<NUM> --output-dir </Path/To/OutputDirectory>
```

## Usage - Genomic range requests via htsget

```bash
usage: pyega3 fetch [-h] [--reference-name REFERENCE_NAME]
                    [--reference-md5 REFERENCE_MD5] [--start START]
                    [--end END] [--format {BAM,CRAM,VCF,BCF}]
                    [--max-retries MAX_RETRIES] [--retry-wait RETRY_WAIT]
                    [--output-dir OUTPUT_DIR] [--delete-temp-files]
                    identifier

positional arguments:
  identifier            Id for dataset (e.g. EGAD00000000001) or file (e.g.
                        EGAF12345678901)

optional arguments:
  -h, --help            show this help message and exit
  --reference-name REFERENCE_NAME, -r REFERENCE_NAME
                        The reference sequence name, for example 'chr1', '1',
                        or 'chrX'. If unspecified, all data is returned.
  --reference-md5 REFERENCE_MD5, -m REFERENCE_MD5
                        The MD5 checksum uniquely representing the requested
                        reference sequence as a lower-case hexadecimal string,
                        calculated as the MD5 of the upper-case sequence
                        excluding all whitespace characters.
  --start START, -s START
                        The start position of the range on the reference,
                        0-based, inclusive. If specified, reference-name or
                        reference-md5 must also be specified.
  --end END, -e END     The end position of the range on the reference,
                        0-based exclusive. If specified, reference-name or
                        reference-md5 must also be specified.
  --format {BAM,CRAM,VCF,BCF}, -f {BAM,CRAM,VCF,BCF}
                        The format of data to request.
  --max-retries MAX_RETRIES, -M MAX_RETRIES
                        The maximum number of times to retry a failed
                        transfer. Any negative number means infinite number of
                        retries.
  --retry-wait RETRY_WAIT, -W RETRY_WAIT
                        The number of seconds to wait before retrying a failed
                        transfer.
  --output-dir OUTPUT_DIR
                        Output directory. The files will be saved into this directory. Must exist. Default: the current working directory.
  --delete-temp-files   Do not keep those temporary, partial files which were
                        left on the disk after a failed transfer.
```
### Using pyEGA3 for fetching a genomic range

*Replace `<these values>` with values relevant for your datasets. Please note that htsget can only be used with files that have corresponding index files in EGA.*

#### Download chromosome 1 for a BAM file

```bash
pyega3 fetch -cf </Path/To/CREDENTIALS_FILE> --reference-name 1 --format BAM --output-dir </Path/To/OutputDirectory> EGAF<NUM>
```

#### Download position 0-1000000 on chromosome 1 for a BAM file

```bash
pyega3 fetch -cf </Path/To/CREDENTIALS_FILE> --start 0 --end 1000000 --reference-name 1 --format BAM --output-dir </Path/To/OutputDirectory> EGAF<NUM>
```

## Troubleshooting

First, please ensure you are using the most recent version of pyEGA3 by following instructions in the "Installation and update" section for updating pyEGA3.

### Failure to validate credentials

Please ensure that your credentials are formatted correctly. Email addresses (usernames) are case-sensitive. If you have an EGA submission account, these credentials are different from your data access credentials. Please ensure you are using your data access credentials with pyEGA3.

### Slow download speeds

Download speed can be optimized using the `--connections` parameter which will parallelize download at the file level. If the `--connections` parameter is provided, all files >100Mb will be downloaded using the specified number of parallel connections.

Using a very high number of connections will introduce overhead that can slow the download of the file. It is important to note that files are still downloaded sequentially, so using multiple connections does not mean downloading multiple files in parallel. We recommend trying with 30 connections initially and adjusting from there to get maximum throughput.

### File taking a long time to save

Please note that when a file is being saved, it goes through two processes. First, the downloaded file "chunks" are pieced back together to reconstruct the original file. Second, pyEGA3 calculates the checksum of the file to confirm the file downloaded successfully. Larger files will take more time to reconstruct and validate the checksum.

### --saveto argument is not recognised

The `--saveto` command-line argument is now called `--output-dir` and, in contrast with the original
`--saveto` argument, one can only specify now an output directory, but not an output file.

This change was made to improve the user experience and avoid issues caused by supplying a filename
where a directory was expected, and vice versa.

Thus, the original command, where the `--saveto` argument specified a directory:

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> fetch EGAF<NUM> --saveto </Path/To/OutputDirectory>
```

should be rewritten like this:

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> fetch EGAF<NUM> --output-dir </Path/To/OutputDirectory>
```

The original command:

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> fetch EGAF<NUM> --saveto </Path/To/NewFileName>
```

where the `--saveto` argument specified a new file-name, is no longer supported,
because the `--output-dir` argument supports only output directories, but not output files.

## Further assistance

If, after troubleshooting an issue, you are still experiencing difficulties, please email EGA Helpdesk (helpdesk@ega-archive.org) with the following information:
* Attach the log file (pyega3_output.log) located in the directory where pyEGA3 is running
* Indicate the compute environment you are running pyEGA3 in: compute cluster, single machine, other (please describe).

## Attribution

Parts of pyEGA3 are derived from [pyEGA](https://github.com/blachlylab/pyega) developed by James Blachly.

## Development
See guide in updating and releasing updates to client in the [Development](development.md) page.
