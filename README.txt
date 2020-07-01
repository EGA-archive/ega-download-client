EGA python client - pyEGA3
pyEGA3 uses the EGA REST API to download authorized datasets and files

Currently works only with Python3

Note: For service level requests, such as no response from the EGA AAI or Data API, please email helpdesk@ega-archive.org

REQUIREMENTS:
Python "requests" module
http://docs.python-requests.org/en/master/
pip3 install requests

Firewall Ports
This client makes https calls to the EGA AAI (https://ega.ebi.ac.uk:8443/) and to the EGA Data API (https://ega.ebi.ac.uk:8052). Both ports 8443 and 8052 must be reachable from the location where this client script is run. Otherwise you will experience timeouts.
(e.g. https://ega.ebi.ac.uk:8443/ega-openid-connect-server/, https://ega.ebi.ac.uk:8052/elixir/central/stats/load should not time out).
----------------------------------------------------------------------------------
INSTALLATION via Pip:
sudo pip3 install pyega3
----------------------------------------------------------------------------------
INSTALLATION via Conda(Bioconda channel):
conda config --add channels bioconda
conda config --add channels conda-forge
conda install pyega3
----------------------------------------------------------------------------------
USAGE:
pyega3 [-h] [-d] -cf CREDENTIALS_FILE [-c CONNECTIONS] {datasets,files,fetch} ...

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
  -t, --test            Use the default test user credential to run the script
  -cf CREDENTIALS_FILE, --credentials-file CREDENTIALS_FILE
                        JSON file containing credentials
                        e.g.{"username":"user1","password":"toor"}
  -sf server_file, --server-file server_file
                        JSON file containing server credentials
                        e.g.{"url_auth":"aai url","url_api":"api url","url_api_ticket":"htsget url","client_secret":"secret"}
  -c CONNECTIONS, --connections CONNECTIONS
                        Download using specified number of connections

----------------------------------------------------------------------------------

How to define your Credential file:
Your username and password are provided to you by EGA.

Create a file called credential_file.json and place it in the directory from where the client will run.
Ideally, this file has to be saved in .json format and should contain your registered EGA email address and EGA password.
Example format https://github.com/EGA-archive/ega-download-client/blob/master/pyega3/config/default_credential_file.json

----------------------------------------------------------------------------------

In order to test/check your usage of the API we have created a test user account which can be used using the following commands:
1. pyega3 -t datasets
2. pyega3 -t files EGAD00001003338
3. pyega3 -t fetch EGAF00001775036

----------------------------------------------------------------------------------

Parallelism ( download via multiple connections ) works on the file level,
but still usable while downloading whole dataset.
If -c command line switch is provided all big files (>100Mb) in the
dataset will be downloaded using specified # of connections.

The number of connections breaks down individual file downloads into segments,
which are then downloaded in parallel. So using a very high number actually
introduces overhead that slows down the download of the file.
Files are still downloaded in sequence – so multiple connections doesn't mean
downloading multiple files in parallel, if an entire dataset is being downloaded.

----------------------------------------------------------------------------------

GENOMIC RANGE REQUESTS ( via Htsget protocol ) :

usage: pyega3 fetch [-h] [--reference-name REFERENCE_NAME]
                    [--reference-md5 REFERENCE_MD5] [--start START]
                    [--end END] [--format {BAM,CRAM}] [--saveto [SAVETO]]
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
                        retries( default value = 5 ).
  --retry-wait RETRY_WAIT, -W RETRY_WAIT
                        The number of seconds to wait before retrying a failed
                        transfer( default value = 5 ).
  --saveto [SAVETO]     Output file(for files)/output dir(for datasets)


How to debug and provide the output to the EGA Helpdesk team?
-------------------------------------------------------------

When attempting your download always make sure that you are using the most up-to-date version of the Python Client, which can be always found on the current page.

We encourage our users facing download failures to contact us here on Helpdesk (ega-helpdesk@ebi.ac.uk). In order to expedite the trouble shooting process we would need the output from your debug attempts. Examples of which are detailed below -

Users facing access issues
--------------------------

nohup pyega3 -d -cf  /Path/To/CREDENTIAL_FILE datasets > /Path/To/Output.txt

Users facing issues listing the files in a dataset
---------------------------------------------------
pyega3 -d -cf  /Path/To/CREDENTIAL_FILE files EGAD00001000740

Users facing download issues
----------------------------
1.Make sure you have access to the dataset/s you are trying to download using the following command

pyega3 -cf  /Path/To/CREDENTIAL_FILE datasets

2.Try to list out the files in the dataset of interest using the following command.

pyega3 -d -cf  /Path/To/CREDENTIAL_FILE files EGAD00000000000

The output of which will also provide you with the file size. It is recommended that you select a file of small size for the next step

3.Finally, please try and pull down this file using the debug mode.

pyega3 -d -cf  /Path/To/CREDENTIAL_FILE fetch EGAF00000000000

The debug flag (-d) will generate a log which can be forwarded to our Helpdesk members. The contents of the debug output will provide us with more clues to the state of your downloads and are needed to query the errors and return codes that your attempts will receive.
