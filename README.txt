EGA python client - pyEGA3
pyEGA3 uses the EGA REST API to download authorized datasets and files

Currently works only with Python3

REQUIREMENTS:
Python "requests" module
http://docs.python-requests.org/en/master/
pip3 install requests

Firewall Ports
This client makes https calls to the EGA AAI (https://ega.ebi.ac.uk:8443/) and to the EGA Data API (https://ega.ebi.ac.uk:8051). Both ports 8443 and 8051 must be reachable from the location where this client script is run. Otherwise you will experience timeouts.
(e.g. https://ega.ebi.ac.uk:8443/ega-openid-connect-server/, https://ega.ebi.ac.uk:8051/elixir/central/stats/load should not time out).
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
  -cf CREDENTIALS_FILE, --credentials-file CREDENTIALS_FILE
                        JSON file containing credentials
                        e.g.{'username':'user1','password':'toor'}
  -c CONNECTIONS, --connections CONNECTIONS
                        Download using specified number of connections                      
                        
----------------------------------------------------------------------------------
  
Credentials file supposed to be in json format e.g:
{
    "username": "my.email@domain.edu",
    "password": "mypassword",    
    "client_secret":"AMenuDLjVdVo4BSwi0QD54LL6NeVDEZRzEQUJ7hJOM3g4imDZBHHX0hNfKHPeQIGkskhtCmqAJtt_jm7EKq-rWw"
}

Your username and password are provided to you by EGA.
Specifying password is not mandatory - if password is not provided 
the user will be asked to enter it from the console

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
  --saveto [SAVETO]     Output file(for files)/output dir(for datasets)


