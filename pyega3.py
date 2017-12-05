import argparse
import os
import sys
import json
import requests
import uuid
from tqdm import tqdm

debug = False
version = "3.0.0"

def load_credentials(filepath):
    """Load credentials for EMBL/EBI EGA from specified file"""
    filepath = os.path.expanduser(filepath)
    if not os.path.exists(filepath): sys.exit("{} does not exist".format(filepath))
        
    try:
        with open(filepath) as f:
            creds = json.load(f)
        if 'username' not in creds or 'password' not in creds or 'client_secret' not in creds:
            sys.exit("{} does not contain either or any of 'username', 'password', or 'client_secret' fields".format(filepath))
    except ValueError:
            sys.exit("invalid JSON file")

    return ( creds['username'], creds['password'], creds['client_secret'], creds.get('key') ) 

def get_token(username, password,client_secret):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    data = ( 
        "grant_type=password&client_id=f20cd2d3-682a-4568-a53e-4262ef54c8f4&scope=openid"
        "&client_secret={}&username={}&password={}").format(client_secret,username, password)
        
    url = "https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token"

    r = requests.post(url, headers = headers, data = data)
    reply = r.json()

    print_debug_info(url, reply)

    try:    
        oauth_token = reply['access_token']
        print("Authentication success for user '{}'".format(username))
    except KeyError:    
        sys.exit("Authentication failure for user '{}'".format(username))               

    return oauth_token

def api_list_authorized_datasets(token):
    """List datasets to which the credentialed user has authorized access"""

    headers = {'Accept':'application/json', 'Authorization': 'Bearer {}'.format(token)} 
    
    url = "https://ega.ebi.ac.uk:8051/elixir/access/datasets"
    r = requests.get(url, headers = headers)
    reply = r.json()

    print_debug_info(url,reply)
    
    if reply is None:
        sys.exit("List authorized datasets failed")    

    return reply

def pretty_print_authorized_datasets(reply):
    print("Dataset ID")
    print("-----------------")
    for datasetid in reply:
        print(datasetid)

def api_list_files_in_dataset(token, dataset):

    headers = {'Accept':'application/json', 'Authorization': 'Bearer {}'.format(token)}         
    url = "https://ega.ebi.ac.uk:8051/elixir/access/datasets/{}/files".format(dataset)
    
    r = requests.get(url, headers = headers)
    reply = r.json()

    print_debug_info(url,reply)

    if reply is None:
        sys.exit("List files in dataset {} failed".format(dataset))
        
    return reply

def pretty_print_files_in_dataset(reply, dataset):
    """
    Print a table of files in authorized dataset from api call api_list_files_in_dataset

        {
           "checksumType": "MD5",
            "checksum": "MD5SUM678901234567890123456789012",
            "fileName": "EGAZ00001314035/b37/NA12878.bam.bai.cip",
            "fileStatus": "available",
            "fileSize": 0,
            "datasetId": "EGAD00001003338",
            "fileId": "EGAF00001753747"
        }
    
    """
    format_string = "{:15} {:6} {:12} {:36} {}"
    
    def status(status_string):
        if (status_string=="available"):   return "ok"
        else: return ""       

    print(format_string.format("File ID", "Status", "Bytes", "Check sum", "File name"))
    for res in reply:
        print(format_string.format( res['fileId'], status(res['fileStatus']) , str(res['fileSize']), res['checksum'], res['fileName'] ))
        

def get_file_name_size(token,file_id):
    headers = {'Accept':'application/json', 'Authorization': 'Bearer {}'.format(token)}         
    url = "https://ega.ebi.ac.uk:8051/elixir/access/files/{}".format(file_id)
                
    r = requests.get(url, headers = headers)
    res = r.json()

    print_debug_info(url,res)

    return ( res['fileName'], res['fileSize'] )

def download_file( token, file_id, file_name, file_size, output_file=None ):
    """Download an individual file"""
    
    print("File: '{}'({} bytes). Download starting ...".format(file_name, file_size)) 

    if output_file is None: output_file=file_name    

    url = "https://ega.ebi.ac.uk:8051/elixir/data/files/{}".format(file_id)    

    dir = os.path.dirname(output_file)
    if not os.path.exists(dir) and len(dir)>0: os.makedirs(dir)

    with open(output_file, 'wb') as fo:
        headers = {'Accept': 'application/octet-stream', 'Authorization': 'Bearer {}'.format(token)}

        r = requests.get(url, headers=headers, stream=True)    
        
        print_debug_info( url, None, "Headers: {}".format(r.headers) )        
        
        with tqdm(total=int(file_size), unit='B', unit_scale=True, unit_divisor=1024) as pbar:
            for chunk in r.iter_content(32*1024):
                fo.write(chunk)
                pbar.update(len(chunk))        

    print("Saved to : '{}'({} bytes)".format(os.path.abspath(output_file), os.path.getsize(output_file)) )


def download_dataset( token, dataset_id ):
    reply = api_list_files_in_dataset(token, dataset_id)    
    for res in reply:
        if (res['fileStatus']=="available"): download_file( token, res['fileId'], res['fileName'], res['fileSize'])        

def print_debug_info(url, reply_json, *args):
    if(not debug): return
    
    print("Request URL : {}".format(url))
    if reply_json is not None: print("Response    : {}".format(json.dumps(reply_json, indent=4)) )

    for a in args: print a        


def main():
    print("EGA python client version {}".format(version))

    parser = argparse.ArgumentParser(description="Download from EMBL EBI's EGA (European Genome-phenome Archive")
    parser.add_argument("-d", "--debug", action="store_true", help="Extra debugging messages")
    parser.add_argument("-cf","--credentials-file", required=True, help="JSON file containing credentials e.g.{'username':'user1','password':'toor','key': 'abc'}")

    subparsers = parser.add_subparsers(dest="subcommand", help = "subcommands")

    parser_ds    = subparsers.add_parser("datasets", help="List authorized datasets")

    parser_dsinfo= subparsers.add_parser("files", help="List files in a specified dataset")
    parser_dsinfo.add_argument("identifier", help="Dataset ID (e.g. EGAD00000000001)")

    parser_fetch = subparsers.add_parser("fetch", help="Fetch a dataset or file")
    parser_fetch.add_argument("identifier", help="Id for dataset (e.g. EGAD00000000001) or file (e.g. EGAF12345678901)")
    parser_fetch.add_argument("outputfile", nargs='?',  help="Output file")
    
    args = parser.parse_args()
    if args.debug:
        global debug
        debug = True
        print("[debugging]")

    (username, password, client_secret, key) = load_credentials(args.credentials_file)
    token = get_token(username, password, client_secret)

    if args.subcommand == "datasets":
        reply = api_list_authorized_datasets(token)
        pretty_print_authorized_datasets(reply)

    if args.subcommand == "files":
        if (args.identifier[3] != 'D'):
            sys.exit("Unrecognized identifier -- only datasets (EGAD...) supported")                        
        reply = api_list_files_in_dataset(token, args.identifier)
        pretty_print_files_in_dataset(reply, args.identifier)

    elif args.subcommand == "fetch":
    
        if (args.identifier[3] == 'D'):
            download_dataset( token, args.identifier )
        elif(args.identifier[3] == 'F'):
            file_name, file_size = get_file_name_size( token, args.identifier )
            download_file( token, args.identifier,  file_name, file_size, args.outputfile)
        else:
            sys.exit("Unrecognized identifier -- only datasets (EGAD...) and and files (EGAF...) supported")            
        

if __name__ == "__main__":
    main()

