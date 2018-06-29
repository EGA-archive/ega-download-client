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
-------------------------------------------------------------------------
INSTALLATION:
sudo pip3 install pyega3
-------------------------------------------------------------------------
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
                        
-------------------------------------------------------------------------
  
Credentials file supposed to be in json format e.g:
{
    "username": "my.email@domain.edu",
    "password": "mypassword",    
    "client_secret":"AMenuDLjVdVo4BSwi0QD54LL6NeVDEZRzEQUJ7hJOM3g4imDZBHHX0hNfKHPeQIGkskhtCmqAJtt_jm7EKq-rWw"
}

Your username and password are provided to you by EGA.
