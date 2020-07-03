# EGA download client: pyEGA3

## Overview

The pyEGA3 download client is a python-based tool used to view and download files from authorized EGA datasets. pyEGA3 uses the EGA Data API and has several key features:
* Files are transferred over secure https connections and received unencrypted so there is no need for decryption after download.
* pyEGA3 supports file segmenting and downloading the segments in parallel, which improves overall performance.
* File download resumes from where it left off if errors or interrupted connections are encountered.
* After download completes, file integrity is verified against the unencrypted MD5 checksum.

### Tutorial Video

[Here](https://embl-ebi.cloud.panopto.eu/Panopto/Pages/Viewer.aspx?id=be79bb93-1737-4f95-b80f-ab4300aa6f5a) is a video tutorial demonstrating the usage of pyEGA3 from installation through file download.

## Requirements

* Python3
* Python `requests` module

```bash
pip3 install requests
```

* If the `requests` module is already installed, we recommend updating to the latest version

```bash
pip3 install requests --upgrade
```

### Firewall Ports

pyEGA3 makes https calls to the EGA AAI (https://ega.ebi.ac.uk:8443/) and the EGA Data API (https://ega.ebi.ac.uk:8052). Ports 8443 and 8052 must both be reachable from the location where pyEGA3 is executed, otherwise timeouts will be encountered.

To check if ports 8443 and 8052 are open, please run the following commands:

```bash
openssl s_client -connect ega.ebi.ac.uk:8443
openssl s_client -connect ega.ebi.ac.uk:8052
```

If the ports are open, both commands will return `Verify return code: 0 (ok)`.

Alternatively, to check if ports 8443 and 8052 are open, both of the following should load with no timeouts:
* https://ega.ebi.ac.uk:8443/ega-openid-connect-server/
* https://ega.ebi.ac.uk:8052/elixir/central/stats/load

## Installation and update

### Using Pip

Install:
```bash
sudo pip3 install pyega3
```

Update:
```bash
pip3 install pyega3 --upgrade
```

### Using conda (bioconda channel)

Install:
```bash
conda config --add channels bioconda
conda config --add channels conda-forge
conda install pyega3
```

Update:
```bash
conda update pyega3
```

### Using GitHub

1. Clone the [ega-download-client GitHub repository](https://github.com/EGA-archive/ega-download-client)

1. Navigate to the directory where the repository was cloned

    ```bash
    cd path/to/ega-download-client
    ```

1. Three scripts are provided to install the required Python environment depending on the host operating system.
    * Linux (Red Hat): red_hat_dependency_install.sh
    * Linux: debian_dependency_install.sh
    * Mac OS: osx_dependency_install.sh

1. Execute the script corresponding to the host operating system. For example, if running Red Hat Linux, use:

    ```bash
    sh red_hat_dependency_install.sh  
    ```

### For Windows users

1. Download Python3 and install following the prompt commands.

1. Verify the correct install from the terminal

    ```bash
    python --version
    ```

1. Upgrade to the latest version of pip

    ```bash
    python -m pip install --upgrade pip
    ```

1. Install the `request`, `tdqm`, and `htsget` modules

    ```bash
    python -m pip install requests
    python -m pip install tdqm
    python -m pip install htsget
    ```

## Usage - File download

```bash
usage: pyega3 [-h] [-d] [-cf CONFIG_FILE] [-sf SERVER_FILE] [-c CONNECTIONS]
              [-t]
              {datasets,files,fetch} ...

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
                        JSON file containing credentials/config
                        e.g.{"username":"user1","password":"toor"}
  -sf SERVER_FILE, --server-file SERVER_FILE
                        JSON file containing server config
                        e.g.{"url_auth":"aai url","url_api":"api url",
                        "url_api_ticket":"htsget url", "client_secret":"client
                        secret"}
  -c CONNECTIONS, --connections CONNECTIONS
                        Download using specified number of connections
  -t, --test            Test user activated
```

### Testing pyEGA3 installation

We recommend that all fresh installations of pyEGA3 be tested. To assist you in accomplishing this, we have created a Test Account which can be used to test the following actions:

1. List the datasets available to the Test Account

    ```bash
    pyega3 -d -t datasets
    ```

1. List the files available in a Test Dataset

    ```bash
    pyega3 -d -t files EGAD00001003338
    ```

1. Download a Test File

    ```bash
    pyega3 -d -t fetch EGAF00001775036
    ```

The Test Account does not require a username and password because it contains files from the [1000 Genomes Project](https://www.internationalgenome.org/data) which is publicly accessible. The files in this Test Dataset can be used both for Troubleshooting and for Training purposes.

Following successful testing of the pyEGA3 installation, you will be able to view and download data from datasets that you have been authorized to access.

### Defining credentials

To view and download files for which you have been granted access, pyEGA3 requires your EGA username (email address) and password in the form of a CREDENTIALS_FILE.

Create a file called CREDENTIALS_FILE and place it in the directory from where pyEGA3 will run. The credentials file must be in JSON format and must contain your registered EGA email address (username) and password provided by EGA Helpdesk.

An example CREDENTIALS_FILE can be found [here](https://github.com/EGA-archive/ega-download-client/blob/master/pyega3/config/default_credential_file.json).

### Using pyEGA3 for file download

Replace `<these values>` with values relevant for your datasets.

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
pyega3 -cf </Path/To/CREDENTIALS_FILE> fetch EGAD<NUM> --saveto </Path/To/Output> 
```

#### Download a single file

```bash
pyega3 -cf </Path/To/CREDENTIALS_FILE> fetch EGAF<NUM> --saveto </Path/To/Output> 
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
pyega3 -c 5 -cf </Path/To/CREDENTIALS_FILE> fetch EGAD<NUM> --saveto </Path/To/Output>
```

## Usage - Genomic range requests via Htsget protocol

```bash
usage: pyega3 fetch [-h] [--reference-name REFERENCE_NAME]
                    [--reference-md5 REFERENCE_MD5] [--start START]
                    [--end END] [--format {BAM,CRAM}]
                    [--max-retries MAX_RETRIES] [--retry-wait RETRY_WAIT]
                    [--saveto [SAVETO]]
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
  --format {BAM,CRAM}, -f {BAM,CRAM}
                        The format of data to request.
  --max-retries MAX_RETRIES, -M MAX_RETRIES
                        The maximum number of times to retry a failed
                        transfer. Any negative number means infinite number of
                        retries.
  --retry-wait RETRY_WAIT, -W RETRY_WAIT
                        The number of seconds to wait before retrying a failed
                        transfer.
  --saveto [SAVETO]     Output file(for files)/output dir(for datasets)
```
### Using pyEGA3 for fetching a genomic range

Replace `<these values>` with values relevant for your datasets. Please note that only files which have corresponding index files in EGA can be used with the Htsget protocol.

#### Download chromosome 1 for a BAM file

```bash
pyega3 fetch -cf </Path/To/CREDENTIALS_FILE> fetch --reference-name 1 --format BAM --saveto </Path/To/Output> EGAF<NUM>
```

#### Download position 0-1000000 on chromosome 1 for a BAM file

```bash
pyega3 fetch -cf </Path/To/CREDENTIALS_FILE> fetch --start 0 --end 10000 --reference-name 1 --format BAM --saveto </Path/To/Output> EGAF<NUM> 
```

## Troubleshooting

First, make sure that you are using the most up-to-date version of pyEGA3 by following instructions for updating pyEGA3 from "Installation and update" section above.

### Failure to validate credentials

Be sure that your credentials are correct. Please note that email addresses (usernames) are case-sensitive. Also note that if you have an EGA submission account, these credentials are different from your data access credentials. Please be sure you are using your data access credentials with pyEGA3. 

### Slow download speeds

Download speed can be optimized using the `--connections` parameter. Download using multiple connections works at the file level, but is still usable while downloading a dataset. If the `--connections` parameter is provided, all files >100Mb will be downloaded using the specified number of connections.

The connections break down the download of individual files into segments, which can be processed in parallel. Using a very high number of connections will introduce an overhead that can slow the download of the file. It is important to note that files are still downloaded sequentially, so using multiple connections does not mean downloading multiple files in parallel.

### File taking a long time to save

Please note that when a file is being saved, it goes through two processes. First, the downloaded file "chunks" have to be pieced back together to reconstruct the original file. Second, pyEGA3 calculates the checksum of the file to confirm the file downloaded successfully. Larger files will take more time to reconstruct and validate the checksum.

## Further assistance

If, after troubleshooting the issue, you are still experiencing difficulties, please email EGA Helpdesk (helpdesk@ega-archive.org) with the following information:
* Attach the <log file name> log file located in the directory where you are running pyEGA3
* Indicate the compute environment you are running pyEGA3 in: compute cluster, single machine, other (please describe)
