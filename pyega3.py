import argparse
import os
import sys
import json
import requests
import uuid
import math
from tqdm import tqdm
import concurrent.futures
import shutil

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
    
    url = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets"
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
    url = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets/{}/files".format(dataset)
    
    r = requests.get(url, headers = headers)
    reply = r.json()

    print_debug_info(url,reply)

    if reply is None:
        sys.exit("List files in dataset {} failed".format(dataset))
        
    return reply

def status_ok(status_string):
    if (status_string=="available"): return True 
    else: return False        

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

    print(format_string.format("File ID", "Status", "Bytes", "Check sum", "File name"))
    for res in reply:
        print(format_string.format( res['fileId'], status_ok(res['fileStatus']) , str(res['fileSize']), res['checksum'], res['fileName'] ))
        

def get_file_name_size(token,file_id):
    headers = {'Accept':'application/json', 'Authorization': 'Bearer {}'.format(token)}         
    url = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/files/{}".format(file_id)
                
    r = requests.get(url, headers = headers)
    res = r.json()

    print_debug_info(url,res)

    return ( res['fileName'], res['fileSize'] )


def download_file_slice( url, headers, file_name, start_pos, length, pbar ):

    CHUNK_SIZE = 32*1024

    if start_pos < 0:
        raise ValueError("start : must be positive")
    if length <= 0:
        raise ValueError("length : must be positive")

    file_name += '-from-'+str(start_pos)+'-len-'+str(length)+'.slice'
    
    with open(file_name, 'wb') as file_out:
        headers['Range'] = 'bytes={}-{}'.format(start_pos,start_pos+length-1)

        print_debug_info( url, None, "Request headers: {}".format(headers) )
        r = requests.get(url, headers=headers, stream=True)               
        print_debug_info( url, None, "Response headers: {}".format(r.headers) )

        r.raise_for_status()           

        for chunk in r.iter_content(CHUNK_SIZE):
            file_out.write(chunk)
            pbar.update(len(chunk))

    return file_name

def download_file_slice_(args):
    return download_file_slice(*args)

def merge_bin_files_on_disk(target_file_name, files_to_merge):
    with open(target_file_name,'wb') as target_file:
        for file_name in files_to_merge:
            with open(file_name,'rb') as f:
                shutil.copyfileobj(f, target_file, 65536)
            os.remove(file_name)

def download_file( token, file_id, file_name, file_size, num_connections, key, output_file=None ):
    """Download an individual file"""

    if( key is not None ):
        raise ValueError('key parameter: encrypted downloads are not supported yet')


    print("File: '{}'({} bytes).".format(file_name, file_size)) 
    num_connections = max( num_connections, 1 ) 
    num_connections = min( num_connections, 128 )
    if( file_size < 100*1024*1024 ): num_connections = 1
    print("Download starting [using {} connection(s)]...".format(num_connections))

    if output_file is None: output_file=file_name    

    url = "https://ega.ebi.ac.uk:8051/elixir/data/files/{}".format(file_id)    

    if( key is None ): url += "?destinationFormat=plain"        

    dir = os.path.dirname(output_file)
    if not os.path.exists(dir) and len(dir)>0: os.makedirs(dir)

    #with open(output_file, 'wb') as fo:

    headers = {}
    #headers['Accept'] = 'application/octet-stream'
    headers['Authorization'] = 'Bearer {}'.format(token)

    chunk_len = math.ceil(file_size/num_connections)

    with tqdm(total=int(file_size), unit='B', unit_scale=True, unit_divisor=1024) as pbar:
        params = [(url, headers, output_file, chunk_start_pos, min(chunk_len,file_size-chunk_start_pos), pbar) for chunk_start_pos in range(0,file_size, chunk_len)]        

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_connections) as executor:    
            for part_file_name in executor.map(download_file_slice_ ,params):
                results.append(part_file_name)

        merge_bin_files_on_disk(output_file, results)
        
    print("Saved to : '{}'({} bytes)".format(os.path.abspath(output_file), os.path.getsize(output_file)) )


def download_dataset( token, dataset_id, num_connections, key ):
    reply = api_list_files_in_dataset(token, dataset_id)    
    for res in reply:
        if ( status_ok(res['fileStatus']) ): download_file( token, res['fileId'], res['fileName'], res['fileSize'], num_connections, key )        

def print_debug_info(url, reply_json, *args):
    if(not debug): return
    
    print("Request URL : {}".format(url))
    if reply_json is not None: print("Response    : {}".format(json.dumps(reply_json, indent=4)) )

    for a in args: print(a)


def main():
    print("EGA python client version {}".format(version))

    parser = argparse.ArgumentParser(description="Download from EMBL EBI's EGA (European Genome-phenome Archive")
    parser.add_argument("-d", "--debug", action="store_true", help="Extra debugging messages")
    parser.add_argument("-cf","--credentials-file", required=True, help="JSON file containing credentials e.g.{'username':'user1','password':'toor','key': 'abc'}")
    parser.add_argument("-c","--connections", type=int, default=1, help="Download using specified number of connections")

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
            download_dataset( token, args.identifier, args.connections, key )
        elif(args.identifier[3] == 'F'):
            file_name, file_size = get_file_name_size( token, args.identifier )
            download_file( token, args.identifier,  file_name, file_size, args.connections, key, args.outputfile )
        else:
            sys.exit("Unrecognized identifier -- only datasets (EGAD...) and and files (EGAF...) supported")            
        

if __name__ == "__main__":
    main()

