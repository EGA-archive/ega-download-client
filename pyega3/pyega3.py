#!/usr/bin/env python3

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
import hashlib
import time
import logging
import htsget
import getpass

version = "3.0.27"
logging_level = logging.INFO

def load_credentials(filepath):
    """Load credentials for EMBL/EBI EGA from specified file"""
    filepath = os.path.expanduser(filepath)
    if not os.path.exists(filepath): sys.exit("{} does not exist".format(filepath))

    try:
        with open(filepath) as f:
            creds = json.load(f)
        if 'username' not in creds or 'client_secret' not in creds:
            sys.exit("{} does not contain either 'username' or 'client_secret' fields".format(filepath))
    except ValueError:
        sys.exit("invalid JSON file")

    if 'password' not in creds:
        creds['password'] = getpass.getpass("Password for '{}':".format(creds['username']))

    return (creds['username'], creds['password'], creds['client_secret'], creds.get('key'))

def get_token(credentials):
    url = "https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token"

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    (username, password, client_secret) = credentials
    data = { "grant_type"   : "password", 
             "client_id"    : "f20cd2d3-682a-4568-a53e-4262ef54c8f4",
             "scope"        : "openid",
             "client_secret": client_secret,
             "username"     : username,
             "password"     : password
            }
        
    r = requests.post( url, headers=headers, data=data )
    logging.debug(r)

    try:
        print('')
        reply = r.json()
        print_debug_info(url, reply)
        r.raise_for_status()
        oauth_token = reply['access_token']
        logging.info("Authentication success for user '{}'".format(username))
    except Exception:
        sys.exit("Authentication failure for user '{}'".format(username))

    return oauth_token

def api_list_authorized_datasets(token):
    """List datasets to which the credentialed user has authorized access"""

    headers = {'Accept':'application/json', 'Authorization': 'Bearer {}'.format(token)} 
    
    url = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets"
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    
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

    if( not dataset in api_list_authorized_datasets(token) ):
        sys.exit("Dataset '{}' is not in the list of your authorized datasets.".format(dataset))        
    
    r = requests.get(url, headers = headers)
    r.raise_for_status()
    logging.debug(r)
    
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

    print( '-' * 80 )
    print( "Total dataset size = %.2f GB " % (sum(r['fileSize'] for r in reply )/(1024*1024*1024.0)) )
        

def get_file_name_size_md5(token, file_id):
    headers = {'Accept':'application/json', 'Authorization': 'Bearer {}'.format(token)}         
    url = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/files/{}".format(file_id)
                
    r = requests.get(url, headers = headers)
    r.raise_for_status()
    res = r.json()

    print_debug_info(url,res)

    if( res['fileName'] is None or res['checksum'] is None ):
        raise RuntimeError("Metadata for file id '{}' could not be retrieved".format(file_id))

    return ( res['fileName'], res['fileSize'], res['checksum'] )


def download_file_slice( url, token, file_name, start_pos, length, pbar=None ):

    CHUNK_SIZE = 32*1024

    if start_pos < 0:
        raise ValueError("start : must be positive")
    if length <= 0:
        raise ValueError("length : must be positive")

    file_name += '-from-'+str(start_pos)+'-len-'+str(length)+'.slice'
    
    existing_size = os.stat(file_name).st_size if os.path.exists(file_name) else 0
    if( existing_size > length ): os.remove(file_name)        
    if pbar: pbar.update( existing_size )

    if( existing_size == length ): return file_name

    headers = {}
    headers['Authorization'] = 'Bearer {}'.format(token)        
    headers['Range'] = 'bytes={}-{}'.format(start_pos+existing_size,start_pos+length-1)

    print_debug_info( url, None, "Request headers: {}".format(headers) )
    r = requests.get(url, headers=headers, stream=True)               
    print_debug_info( url, None, "Response headers: {}".format(r.headers) )

    r.raise_for_status()           

    with open(file_name, 'ba') as file_out:
        for chunk in r.iter_content(CHUNK_SIZE):
            file_out.write(chunk)
            if pbar: pbar.update(len(chunk))

    return file_name

def download_file_slice_(args):
    return download_file_slice(*args)

def merge_bin_files_on_disk(target_file_name, files_to_merge):
    logging.info('Saving...')
    start = time.time()
    
    os.rename( files_to_merge[0], target_file_name)
    logging.debug( files_to_merge[0] )
    
    with open(target_file_name,'ab') as target_file:
        for file_name in files_to_merge[1:]:
            with open(file_name,'rb') as f:
                logging.debug( file_name )
                shutil.copyfileobj(f, target_file, 65536)
            os.remove(file_name)
            
    end = time.time()
    logging.debug('Merged in {} sec'.format(end - start))

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            # print("fff={}, chunk={}".format(fname,chunk[:5] ) )
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def print_local_file_info( prefix_str, file, md5 ):
    logging.info( "{}'{}'({} bytes, md5={})".format(prefix_str, os.path.abspath(file), os.path.getsize(file), md5) )

def print_local_file_info_genomic_range( prefix_str, file, gr_args ):
    logging.info( 
        "{}'{}'({} bytes, referenceName={}, referenceMD5={}, start={}, end={}, format={})".format(
        prefix_str, 
        os.path.abspath(file), os.path.getsize(file), 
        gr_args[0], gr_args[1], gr_args[2], gr_args[3], gr_args[4]) 
    )    


def is_genomic_range(genomic_range_args):
    if not genomic_range_args: return False
    return genomic_range_args[0] is not None or genomic_range_args[1] is not None

def generate_output_filename( folder, file_id, file_name, genomic_range_args ):
    ext_to_remove = ".cip"
    if file_name.endswith(ext_to_remove): file_name = file_name[:-len(ext_to_remove)]
    name, ext = os.path.splitext(os.path.basename(file_name))        

    genomic_range = ''
    if is_genomic_range(genomic_range_args):
        genomic_range = "_genomic_range_"+(genomic_range_args[0] or genomic_range_args[1])
        genomic_range += '_'+(str(genomic_range_args[2]) or '0')
        genomic_range += '_'+(str(genomic_range_args[3]) or '')
        formatExt = '.'+(genomic_range_args[4] or '').strip().lower()
        if formatExt != ext and len(formatExt)>1 : ext += formatExt
    
    ret_val = os.path.join(folder, file_id, name+genomic_range+ext)    
    logging.debug("Output file:'{}'".format(ret_val))
    return ret_val

def download_file( token, file_id, file_size, check_sum, num_connections, key, output_file=None ):
    """Download an individual file"""

    if key is not None:
        raise ValueError('key parameter: encrypted downloads are not supported yet')

    url = "https://ega.ebi.ac.uk:8051/elixir/data/files/{}".format(file_id)

    if( key is None ): url+="?destinationFormat=plain"; file_size-=16 #16 bytes IV not necesary in plain mode

    if( os.path.exists(output_file) and md5(output_file) == check_sum ):
        print_local_file_info('Local file exists:', output_file, check_sum )
        return
    
    num_connections = max( num_connections, 1 ) 
    num_connections = min( num_connections, 128 )
    if( file_size < 100*1024*1024 ): num_connections = 1
    logging.info("Download starting [using {} connection(s)]...".format(num_connections))

    chunk_len = math.ceil(file_size/num_connections)

    with tqdm(total=int(file_size), unit='B', unit_scale=True, unit_divisor=1024) as pbar:
        params = [(url, token, output_file, chunk_start_pos, min(chunk_len,file_size-chunk_start_pos), pbar) for chunk_start_pos in range(0,file_size, chunk_len)]        

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_connections) as executor:
            for part_file_name in executor.map(download_file_slice_ ,params):
                results.append(part_file_name)

        pbar.close()

        if( sum(os.path.getsize(f) for f in results) == file_size  ):
            merge_bin_files_on_disk(output_file, results)
            
    not_valid_server_md5 = len(str(check_sum or ''))!=32
    
    if( md5(output_file) == check_sum or not_valid_server_md5 ):
        print_local_file_info('Saved to : ', output_file, check_sum )
        if not_valid_server_md5: logging.info("WARNING: Unable to obtain valid MD5 from the server(recived:{}). Can't validate download. Contact EGA helpdesk".format(check_sum))
    else:
        os.remove(output_file)
        raise Exception("MD5 does NOT match - corrupted download")

def download_file_retry( token, file_id, file_name, file_size, check_sum, num_connections, key, output_file, genomic_range_args ):
    max_retries = 3
    retry_wait = 5

    if file_name.endswith(".gpg"): 
        logging.info("GPG files are not supported")
        return

    logging.info("File Id: '{}'({} bytes).".format(file_id, file_size))

    if output_file is None: 
        output_file = generate_output_filename(os.getcwd(), file_id, file_name, genomic_range_args)
    dir = os.path.dirname(output_file)
    if not os.path.exists(dir) and len(dir)>0 : os.makedirs(dir)

    if is_genomic_range(genomic_range_args):
        with open(output_file,'wb') as output:
            htsget.get(
                "https://ega.ebi.ac.uk:8051/elixir/data/tickets/files/{}".format(file_id),
                output,
                reference_name=genomic_range_args[0], reference_md5=genomic_range_args[1],
                start=genomic_range_args[2], end=genomic_range_args[3],
                data_format=genomic_range_args[4],
                max_retries=max_retries, retry_wait=retry_wait,
                bearer_token=token)
        print_local_file_info_genomic_range('Saved to : ', output_file, genomic_range_args)            
        return

    done = False
    num_retries = 0
    while not done:
        try:
            download_file(token, file_id, file_size, check_sum, num_connections, key, output_file)
            done = True
        except Exception as e:
            logging.info(e)
            if num_retries == max_retries:
                raise e
            time.sleep(retry_wait)
            num_retries += 1
            logging.info("retry attempt {}".format(num_retries))


def download_dataset( credentials,  dataset_id, num_connections, key, output_dir, genomic_range_args ):
    token = get_token(credentials)

    if( not dataset_id in api_list_authorized_datasets(token) ):
        logging.info("Dataset '{}' is not in the list of your authorized datasets.".format(dataset_id))    
        return

    reply = api_list_files_in_dataset(token, dataset_id)    
    for res in reply:
        try:
            if ( status_ok(res['fileStatus']) ):
                output_file = None if( output_dir is None ) else generate_output_filename(output_dir, res['fileId'], res['fileName'], genomic_range_args)
                download_file_retry( token, res['fileId'], res['fileName'], res['fileSize'], res['checksum'], num_connections, key, output_file, genomic_range_args )        
                token = get_token(credentials)
        except Exception as e: logging.info(e)

def print_debug_info(url, reply_json, *args):
    logging.debug("Request URL : {}".format(url))
    if reply_json is not None: logging.debug("Response    :\n %.1200s" % json.dumps(reply_json, indent=4) )

    for a in args: logging.debug(a)


def main():
    print("EGA python client version {}".format(version))

    parser = argparse.ArgumentParser(description="Download from EMBL EBI's EGA (European Genome-phenome Archive)")
    parser.add_argument("-d", "--debug", action="store_true", help="Extra debugging messages")
    parser.add_argument("-cf","--credentials-file", required=True, help="JSON file containing credentials e.g.{'username':'user1','password':'toor','key': 'abc'}")
    parser.add_argument("-c","--connections", type=int, default=1, help="Download using specified number of connections")

    subparsers = parser.add_subparsers(dest="subcommand", help = "subcommands")

    parser_ds    = subparsers.add_parser("datasets", help="List authorized datasets")

    parser_dsinfo= subparsers.add_parser("files", help="List files in a specified dataset")
    parser_dsinfo.add_argument("identifier", help="Dataset ID (e.g. EGAD00000000001)")

    parser_fetch = subparsers.add_parser("fetch", help="Fetch a dataset or file")
    parser_fetch.add_argument("identifier", help="Id for dataset (e.g. EGAD00000000001) or file (e.g. EGAF12345678901)")

    parser_fetch.add_argument(
        "--reference-name", "-r", type=str, default=None,
        help=(
            "The reference sequence name, for example 'chr1', '1', or 'chrX'. "
            "If unspecified, all data is returned."))
    parser_fetch.add_argument(
        "--reference-md5", "-m", type=str, default=None,
        help=(
            "The MD5 checksum uniquely representing the requested reference "
            "sequence as a lower-case hexadecimal string, calculated as the MD5 "
            "of the upper-case sequence excluding all whitespace characters."))
    parser_fetch.add_argument(
        "--start", "-s", type=int, default=None,
        help=(
            "The start position of the range on the reference, 0-based, inclusive. "
            "If specified, reference-name or reference-md5 must also be specified."))
    parser_fetch.add_argument(
        "--end", "-e", type=int, default=None,
        help=(
            "The end position of the range on the reference, 0-based exclusive. If "
            "specified, reference-name or reference-md5 must also be specified."))
    parser_fetch.add_argument(
        "--format", "-f", type=str, default=None, choices=["BAM","CRAM"], help="The format of data to request.")
        
    parser_fetch.add_argument("--saveto", nargs='?',  help="Output file(for files)/output dir(for datasets)")
        
    args = parser.parse_args()
    if args.debug:
        global logging_level
        logging_level = logging.DEBUG
        print("[debugging]")

    logging.basicConfig(level=logging_level, format='%(asctime)s %(message)s', datefmt='[%Y-%m-%d %H:%M:%S %z]')

    *credentials, key = load_credentials(args.credentials_file)
    token = get_token(credentials)

    if args.subcommand == "datasets":
        reply = api_list_authorized_datasets(token)
        pretty_print_authorized_datasets(reply)

    if args.subcommand == "files":
        if (args.identifier[3] != 'D'):
            sys.exit("Unrecognized identifier -- only datasets (EGAD...) supported")                        
        reply = api_list_files_in_dataset(token, args.identifier)
        pretty_print_files_in_dataset(reply, args.identifier)

    elif args.subcommand == "fetch":        
        genomic_range_args = ( args.reference_name, args.reference_md5, args.start, args.end, args.format )
        if (args.identifier[3] == 'D'):
            download_dataset( credentials, args.identifier, args.connections, key, args.saveto, genomic_range_args )
        elif(args.identifier[3] == 'F'):
            file_name, file_size, check_sum = get_file_name_size_md5( token, args.identifier )            
            download_file_retry( token, args.identifier, file_name, file_size, check_sum, args.connections, key, args.saveto, genomic_range_args )
        else:
            sys.exit("Unrecognized identifier -- only datasets (EGAD...) and and files (EGAF...) supported")            
        

if __name__ == "__main__":
    main()
    
