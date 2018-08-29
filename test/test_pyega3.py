
import os
import re
import sys
import json
import random
import string
import hashlib
import requests
import responses
import unittest
from unittest import mock

from urllib import parse
from psutil import virtual_memory
from collections import namedtuple

import pyega3.pyega3 as pyega3

def random_string(length):
    return ''.join(random.choice(string.ascii_letters+string.digits) for m in range(length))
def rand_str(min_len=6, max_len=127):
    return random_string(random.randint(1, max_len))

class Pyega3Test(unittest.TestCase):
    def test_load_credentials(self):
        
        with mock.patch('os.path.exists') as m:
            m.return_value = True

            good_creds={"username":rand_str(),"password":rand_str(),"key":rand_str(),"client_secret":rand_str()}
            m_open = mock.mock_open(read_data=json.dumps(good_creds))
            with mock.patch( "builtins.open", m_open ):                
                good_credentials_file = "credentials.json"
                result = pyega3.load_credentials(good_credentials_file)
                m_open.assert_called_once_with(good_credentials_file)
                self.assertEqual(len(result) , 4                     )
                self.assertEqual(result[0]   , good_creds["username"]      )
                self.assertEqual(result[1]   , good_creds["password"]      )
                self.assertEqual(result[2]   , good_creds["client_secret"] )
                self.assertEqual(result[3]   , good_creds["key"]           ) 

            bad_creds={"notusername":rand_str(),"password":rand_str(),"key":rand_str(),"client_secret":rand_str()}
            with mock.patch( "builtins.open", mock.mock_open(read_data=json.dumps(bad_creds)) ):         
                with self.assertRaises(SystemExit):
                    bad_credentials_file = "bad_credentials.json"                
                    result = pyega3.load_credentials(bad_credentials_file)

            with mock.patch( "builtins.open", mock.mock_open(read_data="bad json") ):         
                with self.assertRaises(SystemExit):
                    bad_credentials_file = "bad_credentials.json"                
                    result = pyega3.load_credentials(bad_credentials_file)

    @responses.activate    
    def test_get_token(self):        
        url  =  "https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token"

        id_token     = rand_str()
        access_token = rand_str()          

        good_credentials = (rand_str(), rand_str(), rand_str())

        def request_callback(request):
            
            query = parse.parse_qs( request.body )
            if query['username'][0] == good_credentials[0] and query['password'][0] == good_credentials[1]:
                return ( 200, {}, json.dumps({"access_token": access_token, "id_token": id_token, "token_type": "Bearer", "expires_in": 3600 }) )
            else:
                return ( 400, {}, json.dumps({"error_description": "Bad credentials","error": "invalid_grant"}) )
                
        responses.add_callback(
            responses.POST, url,
            callback=request_callback,
            content_type='application/json',
            )        

        resp_token = pyega3.get_token(good_credentials)
        self.assertEqual( resp_token, access_token )

        bad_credentials = (rand_str(), rand_str(), rand_str())
        with self.assertRaises(SystemExit):
            pyega3.get_token(bad_credentials)                                

    @responses.activate    
    def test_api_list_authorized_datasets(self):        
        url = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets"

        good_token = rand_str()       
        datasets = ["EGAD00000000001", "EGAD00000000002","EGAD00000000003"]

        def request_callback(request):   
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps(datasets) )
            else:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )
                
        responses.add_callback(
            responses.GET, url,
            callback=request_callback,
            content_type='application/json',
            )                

        resp_json = pyega3.api_list_authorized_datasets(good_token)
        self.assertEqual( len(resp_json), 3 )
        self.assertEqual( resp_json[0], datasets[0] )
        self.assertEqual( resp_json[1], datasets[1] )
        self.assertEqual( resp_json[2], datasets[2] )

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.api_list_authorized_datasets(bad_token)

    @responses.activate    
    def test_api_list_files_in_dataset(self): 

        dataset = "EGAD00000000001"

        responses.add(
                responses.GET, 
                "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets",
                json=json.dumps([dataset]), status=200)

        url_files = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets/{}/files".format(dataset)        

        files = [
        {
            "checksum": "3b89b96387db5199fef6ba613f70e27c",
            "datasetId": dataset,
            "fileStatus": "available",
            "fileId": "EGAF00000000001",
            "checksumType": "MD5",
            "fileSize": 4804928,
            "fileName": "EGAZ00000000001/ENCFF000001.bam"
        },
        {
            "checksum": "b8ae14d5d1f717ab17d45e8fc36946a0",
            "datasetId": dataset,
            "fileStatus": "available",
            "fileId": "EGAF00000000002",
            "checksumType": "MD5",
            "fileSize": 5991400,
            "fileName": "EGAZ00000000002/ENCFF000002.bam"
        } ]

        good_token = rand_str()

        def request_callback(request):   
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps(files) )
            else:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )
                
        responses.add_callback(
            responses.GET, url_files,
            callback=request_callback,
            content_type='application/json',
            )        

        resp_json = pyega3.api_list_files_in_dataset(good_token, dataset)
        
        self.assertEqual( len(resp_json), 2 )
        self.assertEqual( resp_json[0], files[0] )
        self.assertEqual( resp_json[1], files[1] )

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.api_list_files_in_dataset(bad_token, dataset)

        bad_dataset  = rand_str()
        with self.assertRaises(SystemExit):
            pyega3.api_list_files_in_dataset(good_token, bad_dataset)

    @responses.activate    
    def test_get_file_name_size_md5(self):      

        good_file_id = "EGAF00000000001"
        file_size    = 4804928
        file_name    = "EGAZ00000000001/ENCFF000001.bam"
        check_sum    = "3b89b96387db5199fef6ba613f70e27c"

        good_token = rand_str()       

        def request_callback(request):   
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps({"fileName": file_name, "fileSize": file_size, "checksum": check_sum}) )
            else:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )
                
        responses.add_callback(
            responses.GET, 
            "https://ega.ebi.ac.uk:8051/elixir/data/metadata/files/{}".format(good_file_id),
            callback=request_callback,
            content_type='application/json',
            )                

        rv = pyega3.get_file_name_size_md5(good_token, good_file_id)
        self.assertEqual( len(rv), 3 )
        self.assertEqual( rv[0], file_name )
        self.assertEqual( rv[1], file_size )
        self.assertEqual( rv[2], check_sum )

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.get_file_name_size_md5(bad_token, good_file_id)

        bad_file_id = "EGAF00000000000"
        with self.assertRaises(requests.exceptions.ConnectionError):
            pyega3.get_file_name_size_md5(good_token, bad_file_id)

        bad_file_id_2 = "EGAF00000000666"
        responses.add(
            responses.GET, 
            "https://ega.ebi.ac.uk:8051/elixir/data/metadata/files/{}".format(bad_file_id_2),
            json={"fileName": None, "checksum": None}, status=200)            
        with self.assertRaises(RuntimeError):
            pyega3.get_file_name_size_md5(good_token, bad_file_id_2)
  
    @responses.activate    
    def test_download_file_slice(self):

        good_url = "https://good_test_server_url"
        good_token = rand_str() 

        mem             = virtual_memory().available
        file_length     = random.randint(1, mem//512)
        slice_start     = random.randint(0,file_length)
        slice_length    = random.randint(0,file_length-slice_start)
        file_name       = rand_str()
        file_contents   = os.urandom(file_length)

        def parse_ranges(s):
            return tuple(map(int,re.match(r'^bytes=(\d+)-(\d+)$', s).groups()))

        def request_callback(request):
            auth_hdr = request.headers['Authorization']
            if auth_hdr is None or auth_hdr != 'Bearer ' + good_token:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )

            start, end = parse_ranges( request.headers['Range'] )
            self.assertLess(start,end)                              
            return ( 200, {}, file_contents[start:end+1] )
                
        responses.add_callback(
            responses.GET, 
            good_url,
            callback=request_callback
            )                
        
        self.written_bytes = 0        
        def mock_write(buf):
            buf_len = len(buf) 
            expected_buf = file_contents[slice_start+self.written_bytes:slice_start+self.written_bytes+buf_len]
            self.assertEqual( expected_buf, buf )               
            self.written_bytes += buf_len
        
        m_open = mock.mock_open()
        with mock.patch( "builtins.open", m_open, create=True ):  
            m_open().write.side_effect = mock_write
            pyega3.download_file_slice(good_url, good_token, file_name, slice_start, slice_length)        
            self.assertEqual( slice_length, self.written_bytes )

        fname_on_disk = file_name + '-from-'+str(slice_start)+'-len-'+str(slice_length)+'.slice'
        m_open.assert_called_with(fname_on_disk, 'ba')

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.download_file_slice(good_url, bad_token, file_name, slice_start, slice_length)

        bad_url = "https://bad_test_server_url"
        with self.assertRaises(requests.exceptions.ConnectionError):
            pyega3.download_file_slice(bad_url, good_token, file_name, slice_start, slice_length)

        with self.assertRaises(ValueError):
            pyega3.download_file_slice(rand_str(), rand_str(), file_name, -1, slice_length)

        with self.assertRaises(ValueError):
            pyega3.download_file_slice(rand_str(), rand_str(), file_name, slice_start, -1)


    @mock.patch('os.remove')
    def test_merge_bin_files_on_disk(self, mocked_remove):        
        mem = virtual_memory().available        
        files_to_merge = {
            'f1.bin' : os.urandom(random.randint(1, mem//512)), 
            'f2.bin' : os.urandom(random.randint(1, mem//512)), 
            'f3.bin' : os.urandom(random.randint(1, mem//512)), 
        }
        target_file_name = "merged.file"

        merged_bytes = bytearray()
        def mock_write(buf): merged_bytes.extend(buf)

        real_open = open
        def open_wrapper(filename, mode):       
            if filename == target_file_name:
                file_object = mock.mock_open().return_value
                file_object.write.side_effect = mock_write
                return file_object
            if filename not in files_to_merge:
                return real_open(filename, mode)
            content = files_to_merge[filename] 
            length = len(content)
            buf_size = 65536
            file_object = mock.mock_open(read_data=content).return_value
            file_object.__iter__.return_value = [content[i:min(i+buf_size,length)] for i in range(0,length,buf_size)]   
            return file_object        
        

        with mock.patch('builtins.open', new=open_wrapper):
            pyega3.merge_bin_files_on_disk(target_file_name, files_to_merge)

        mocked_remove.assert_has_calls( [mock.call(f) for f in files_to_merge.keys()] )

        verified_bytes = 0
        for f_content in files_to_merge.values():
            f_len = len(f_content)
            self.assertEqual( f_content, merged_bytes[ verified_bytes : verified_bytes+f_len ] )
            verified_bytes += f_len           

        self.assertEqual( verified_bytes, len(merged_bytes) )

    def test_md5(self):

        test_list = [
                ("d41d8cd98f00b204e9800998ecf8427e", b""),
                ("0cc175b9c0f1b6a831c399e269772661", b"a"),
                ("900150983cd24fb0d6963f7d28e17f72", b"abc"),
                ("f96b697d7cb7938d525a2f31aaf161d0", b"message digest"),
                ("c3fcd3d76192e4007dfb496cca67e13b", b"abcdefghijklmnopqrstuvwxyz"),
                ("d174ab98d277d9f5a5611c2c9f419d9f", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
                ("57edf4a22be3c955ac49da2e2107b67a", b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")
        ]

        for md5, data in test_list:
            m_open = mock.mock_open(read_data=data)
            with mock.patch( "builtins.open", m_open ):                
                result = pyega3.md5(rand_str())
                self.assertEqual(md5, result)
    
    @responses.activate
    @mock.patch('os.remove')
    def test_download_file(self,mocked_remove):        
        file_id = "EGAF00000000001"
        url     = "https://ega.ebi.ac.uk:8051/elixir/data/files/{}".format(file_id)        
        good_token = rand_str() 

        mem             = virtual_memory().available
        file_sz         = random.randint(1, mem//512)
        file_name       = "resulting.file"
        file_contents   = os.urandom(file_sz)         
        file_md5        = hashlib.md5(file_contents).hexdigest()

        mocked_files = {}        
        def open_wrapper(filename, mode):
            filename = os.path.basename(filename)
            if filename not in mocked_files :
                mocked_files[filename] = bytearray()
            content     = bytes(mocked_files[filename])
            content_len = len(content)
            read_buf_sz = 65536
            file_object = mock.mock_open(read_data=content).return_value
            file_object.__iter__.return_value = [content[i:min(i+read_buf_sz,content_len)] for i in range(0,content_len,read_buf_sz)]
            file_object.write.side_effect = lambda write_buf: mocked_files[filename].extend(write_buf)
            return file_object

        def parse_ranges(s):
            return tuple(map(int,re.match(r'^bytes=(\d+)-(\d+)$', s).groups()))

        def request_callback(request):
            auth_hdr = request.headers['Authorization']
            if auth_hdr is None or auth_hdr != 'Bearer ' + good_token:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )

            start, end = parse_ranges( request.headers['Range'] )
            self.assertLess(start,end)                              
            return ( 200, {}, file_contents[start:end+1] )
                
        responses.add_callback(
            responses.GET, 
            url,
            callback=request_callback
            )                
        with mock.patch('builtins.open', new=open_wrapper): 
             with mock.patch('os.makedirs', lambda path: None):
                with mock.patch('os.path.exists', lambda path: os.path.basename(path) in mocked_files):
                    def os_stat_mock(fn):
                        fn=os.path.basename(fn)                        
                        X = namedtuple('X','st_size f1 f2 f3 f4 f5 f6 f7 f8 f9')
                        sr = [None] * 10; sr[0]=len(mocked_files[fn]); return X(*sr)
                    with mock.patch('os.stat', os_stat_mock):
                        pyega3.download_file( 
                            # add 16 bytes to file size ( IV adjustment )
                            good_token, file_id, file_name+".cip", file_sz+16, file_md5, 1, None, output_file=None ) 
                        self.assertEqual( file_contents, mocked_files[file_name] )

                        pyega3.download_file_retry( 
                            good_token, file_id, file_name+".cip", file_sz+16, file_md5, 1, None, output_file=None ) 

                        wrong_md5 = "wrong_md5_exactly_32_chars_longg"
                        pyega3.download_file( 
                            good_token, file_id, file_name+".cip", file_sz+16, wrong_md5, 1, None, output_file=None ) 

                        mocked_remove.assert_has_calls( 
                            [mock.call(os.path.join( os.getcwd(), file_id, os.path.basename(f) )) for f in mocked_files.keys()],
                            any_order=True )

        with self.assertRaises(ValueError):
            pyega3.download_file_retry( "", "", "", 0, 0, 1, "key", output_file=None ) 

        pyega3.download_file( "", "", "test.gpg",  0, 0, 1, None, output_file=None ) 

    @responses.activate    
    @mock.patch("pyega3.pyega3.download_file_retry")
    def test_download_dataset(self, mocked_dfr):         

        good_dataset = "EGAD00000000001"               
        
        file1_sz       = 4804928
        file1_contents = os.urandom(file1_sz)
        file1_md5      = hashlib.md5(file1_contents).hexdigest()

        file2_sz       = 5991400
        file2_contents = os.urandom(file2_sz)
        file2_md5      = hashlib.md5(file2_contents).hexdigest()

        files = [
        {
            "fileStatus": "not_available"
        },
        {
            "checksum": file1_md5,
            "datasetId": good_dataset,
            "fileStatus": "available",
            "fileId": "EGAF00000000001",
            "checksumType": "MD5",
            "fileSize": file1_sz,
            "fileName": "EGAZ00000000001/ENCFF000001.bam"
        },
        {
            "checksum": file2_md5,
            "datasetId": good_dataset,
            "fileStatus": "available",
            "fileId": "EGAF00000000002",
            "checksumType": "MD5",
            "fileSize": file2_sz,
            "fileName": "EGAZ00000000002/ENCFF000002.bam"
        } ]                     
              
        with mock.patch("pyega3.pyega3.get_token", lambda creds: 'token' ):
            with mock.patch("pyega3.pyega3.api_list_authorized_datasets", lambda token: [good_dataset]):        
                with mock.patch("pyega3.pyega3.api_list_files_in_dataset", lambda token, dataset_id: files ):                
                    creds={"username":rand_str(),"password":rand_str(),"client_secret":rand_str()}
                    num_connections = 1
                    bad_dataset = "EGAD00000000666"
                    pyega3.download_dataset( creds, bad_dataset, num_connections, None, None )
                    self.assertEqual( 0, mocked_dfr.call_count )
                
                    pyega3.download_dataset( creds, good_dataset, num_connections, None, None )
                    self.assertEqual( len(files)-1, mocked_dfr.call_count )

                    mocked_dfr.assert_has_calls( 
                        [mock.call('token', f['fileId'], f['fileName'], f['fileSize'],f['checksum'],num_connections,None,None) for f in files if f["fileStatus"]=="available"] )

if __name__ == '__main__':
    unittest.main(exit=False)
