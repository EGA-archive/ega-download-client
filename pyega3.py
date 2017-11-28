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
        if 'username' not in creds or 'password' not in creds or 'key' not in creds:
            sys.exit("{} does not contain either or any of 'username', 'password', or 'key' fields".format(filepath))
    except ValueError:
            sys.exit("invalid JSON file")

    return (creds['username'], creds['password'], creds['key'])

def get_token(username, password):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    data = ( 
        "grant_type=password&client_id=f20cd2d3-682a-4568-a53e-4262ef54c8f4"
        "&client_secret=AMenuDLjVdVo4BSwi0QD54LL6NeVDEZRzEQUJ7hJOM3g4imDZBHHX0hNfKHPeQIGkskhtCmqAJtt_jm7EKq-rWw"
        "&username={}&password={}&scope=openid").format(username, password)
        
    url = "https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token"

    r = requests.post(url, headers = headers, data = data)
    if (debug): print( json.dumps(r.text, indent=4) ) 
    reply = r.json()
    
    oauth_token = reply['access_token']
    
    if oauth_token is None:
        sys.exit("Login failure for user {}".format(username))        
    else:        
        print("Login success for user {}".format(username))        

    return oauth_token

def api_list_authorized_datasets(token):
    """List datasets to which the credentialed user has authorized access"""

    headers = {'Accept':'application/json', 'Authorization': 'Bearer {}'.format(token)} 
    
    url = "https://ega.ebi.ac.uk:8051/elixir/access/datasets"
    r = requests.get(url, headers = headers)
    reply = r.json()
    if(debug):  print( json.dumps(reply, indent=4) )
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
    if(debug):  print( json.dumps(reply, indent=4) )
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

def download_request(req_ticket):
    
    if req_ticket['header']['userMessage'] != "OK":
        print("download_request(): request ticket status Not ok")
        sys.exit(1)

    nresults = req_ticket['response']['numTotalResults']
    print("Number of results: {}".format(nresults))

    for res in req_ticket['response']['result']:
        remote_filename = res['fileName']
        remote_filesize = res['fileSize']
        
        local_filename = os.path.split(remote_filename)[1]

        dl_ticket = res['ticket']
        api_download_ticket(dl_ticket, local_filename, remote_filesize)

def progress(count, total, suffix=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
       
    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', suffix))
    sys.stdout.flush()  # As suggested by Rom Ruben

def get_file_name_size(token,file_id):
    headers = {'Accept':'application/json', 'Authorization': 'Bearer {}'.format(token)}         
    url = "https://ega.ebi.ac.uk:8051/elixir/access/files/{}".format(file_id)
                
    r = requests.get(url, headers = headers)
    res = r.json()
    if(debug):  print( json.dumps(res, indent=4) )

    return ( res['fileName'], res['fileSize'] )

def download_file( token, file_id ):
    """Download an individual file"""

    file_name, file_size = get_file_name_size(token, file_id)
    print("Downloading: {}({} bytes)".format(file_name, file_size))
    

    url = "https://ega.ebi.ac.uk:8051/elixir/data/files/{}".format(file_id)
    
    if (debug): 
        print("Requesting: {}".format(url))
        print("Saving to: {}".format(file_name))

    if not os.path.exists(os.path.dirname(file_name)):    
        os.makedirs(os.path.dirname(file_name))

    with open(file_name, 'wb') as fo:
        headers = {'Accept': 'application/octet-stream', 'Authorization': 'Bearer {}'.format(token)}

        r = requests.get(url, headers=headers, stream=True)    
        
        if (debug): print( json.dumps(r.text, indent=4) )        
        if (debug): print( "Stream size={}".format(int(r.headers.get('content-length', 0))) )
        
        so_far_bytes = 0 
        #for chunk in r.iter_content(32*1024): 
        with tqdm(total=int(file_size), unit='B', unit_scale=True, unit_divisor=1024) as pbar:
            for chunk in r.iter_content(32*1024):
                if True: # filter out keep-alive new chunks
                    fo.write(chunk)
                    pbar.update(len(chunk))
                    #so_far_bytes+=len(chunk)
                    #progress(so_far_bytes, size, "progress: {}/{}".format(so_far_bytes, total_size))            
        
        #fo.write(r.content)

def main():
    print("EGA python  client version {}".format(version))

    parser = argparse.ArgumentParser(description="Download from EMBL EBI's EGA (European Genome-phenome Archive")
    parser.add_argument("-d", "--debug", action="store_true", help="Extra debugging messages")
    parser.add_argument("-cf","--credentials-file", required=True, help="JSON file containing credentials e.g.{'username':'user1','password':'toor','key': 'abc'}")

    subparsers = parser.add_subparsers(dest="subcommand", help = "subcommands")

    parser_ds    = subparsers.add_parser("datasets", help="List authorized datasets")

    parser_dsinfo= subparsers.add_parser("files", help="List files in a specified dataset")
    parser_dsinfo.add_argument("identifier", help="Dataset ID (e.g. EGAD00000000001)")

    parser_fetch = subparsers.add_parser("fetch", help="Fetch a dataset or file")
    parser_fetch.add_argument("identifier", help="Id for dataset (e.g. EGAD00000000001) or file (e.g. EGAF12345678901)")
    
    args = parser.parse_args()
    if args.debug:
        global debug
        debug = True
        print("[debugging]")

    (username, password, key) = load_credentials(args.credentials_file)
    token = get_token(username, password)

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
            id_type = "datasets"
        elif(args.identifier[3] == 'F'):
            id_type = "files"
        else:
            sys.exit("Unrecognized identifier -- only datasets (EGAD...) and and files (EGAF...) supported")
        download_file(token,args.identifier)

if __name__ == "__main__":
    main()

