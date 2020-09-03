
import os
import re
import sys
import json
import random
import string
import hashlib
import tempfile

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

    def setUp(self):
        # Reset the global variables to make the tests less dependent on each other:
        pyega3.URL_AUTH = ''
        pyega3.URL_API = ''
        pyega3.URL_API_TICKET = ''
        pyega3.CLIENT_SECRET = ''
        pyega3.TEMPORARY_FILES = set()
        pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = False

    def test_load_credentials(self):

        with mock.patch('os.path.exists') as m:
            m.return_value = True

            good_creds={"username":rand_str(),"password":rand_str()}
            m_open = mock.mock_open(read_data=json.dumps(good_creds))
            with mock.patch( "builtins.open", m_open ):
                good_credentials_file = "credentials.json"
                result = pyega3.load_credential(good_credentials_file)
                m_open.assert_called_once_with(good_credentials_file)
                self.assertEqual(len(result) , 3                     )
                self.assertEqual(result[0]   , good_creds["username"]      )
                self.assertEqual(result[1]   , good_creds["password"]      )

            password1 = rand_str()
            good_creds1={"username":rand_str()}
            m_open1 = mock.mock_open(read_data=json.dumps(good_creds1))
            with mock.patch( "builtins.open", m_open1 ):
                with mock.patch( "getpass.getpass" ) as m_get_pw :
                    m_get_pw.return_value = password1
                    good_credentials_file1 = "credentials1.json"
                    result1 = pyega3.load_credential(good_credentials_file1)
                    m_open1.assert_called_once_with(good_credentials_file1)
                    self.assertEqual(len(result1) , 3                     )
                    self.assertEqual(result1[0]   , good_creds1["username"]      )
                    self.assertEqual(result1[1]   , password1                    )

            with mock.patch( "builtins.open", mock.mock_open(read_data="bad json") ):
                with self.assertRaises(SystemExit):
                    bad_credentials_file = "bad_credentials.json"
                    result = pyega3.load_credential(bad_credentials_file)

    @responses.activate
    def test_get_token(self):
        pyega3.URL_AUTH = 'https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token'
        url  =  "https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token"

        id_token     = rand_str()
        access_token = rand_str()

        good_credentials = (rand_str(), rand_str())

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

        bad_credentials = (rand_str(), rand_str())
        with self.assertRaises(SystemExit):
            pyega3.get_token(bad_credentials)

    @responses.activate
    def test_api_list_authorized_datasets(self):
        pyega3.URL_API = 'https://ega.ebi.ac.uk:8052/elixir/data'
        url = "https://ega.ebi.ac.uk:8052/elixir/data/metadata/datasets"

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
    def test_api_list_authorized_datasets_user_has_no_dataset(self):
        pyega3.URL_API = 'https://ega.ebi.ac.uk:8052/elixir/data'
        url = "https://ega.ebi.ac.uk:8052/elixir/data/metadata/datasets"

        good_token = rand_str()
        datasets = None

        def request_callback(request):
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps(datasets) )

        responses.add_callback(
            responses.GET, url,
            callback=request_callback,
            content_type='application/json',
        )

        with self.assertRaises(SystemExit):
            pyega3.api_list_authorized_datasets(good_token)

    @responses.activate
    def test_api_list_files_in_dataset(self):
        pyega3.URL_API = 'https://ega.ebi.ac.uk:8052/elixir/data'

        dataset = "EGAD00000000001"

        responses.add(
            responses.GET,
            "https://ega.ebi.ac.uk:8052/elixir/data/metadata/datasets",
            json=json.dumps([dataset]), status=200)

        url_files = "https://ega.ebi.ac.uk:8052/elixir/data/metadata/datasets/{}/files".format(dataset)

        files = [
            {
                "unencryptedChecksum": "3b89b96387db5199fef6ba613f70e27c",
                "datasetId": dataset,
                "fileStatus": "available",
                "fileId": "EGAF00000000001",
                "checksumType": "MD5",
                "fileSize": 4804928,
                "fileName": "EGAZ00000000001/ENCFF000001.bam",
                "displayFileName": "ENCFF000001.bam"
            },
            {
                "unencryptedChecksum": "b8ae14d5d1f717ab17d45e8fc36946a0",
                "datasetId": dataset,
                "fileStatus": "available",
                "fileId": "EGAF00000000002",
                "checksumType": "MD5",
                "fileSize": 5991400,
                "fileName": "EGAZ00000000002/ENCFF000002.bam",
                "displayFileName": "ENCFF000002.bam"
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
    def test_api_list_files_when_no_file_in_dataset(self):
        pyega3.URL_API = 'https://ega.ebi.ac.uk:8052/elixir/data'
        dataset = "EGAD00000000001"
        responses.add(
            responses.GET,
            "https://ega.ebi.ac.uk:8052/elixir/data/metadata/datasets",
            json=json.dumps([dataset]), status=200)
        url_files = "https://ega.ebi.ac.uk:8052/elixir/data/metadata/datasets/{}/files".format(dataset)
        files = None
        good_token = rand_str()

        def request_callback(request):
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps(files) )

        responses.add_callback(
            responses.GET, url_files,
            callback=request_callback,
            content_type='application/json',
        )

        with self.assertRaises(SystemExit):
            pyega3.api_list_files_in_dataset(good_token, dataset)

    @responses.activate
    def test_get_file_name_size_md5(self):
        pyega3.URL_API = 'https://ega.ebi.ac.uk:8052/elixir/data'

        good_file_id = "EGAF00000000001"
        file_size    = 4804928
        file_name    = "EGAZ00000000001/ENCFF000001.bam"
        display_file_name    = "ENCFF000001.bam"
        check_sum    = "3b89b96387db5199fef6ba613f70e27c"

        good_token = rand_str()

        def request_callback(request):
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps({"displayFileName": display_file_name, "fileName": file_name, "displayFileName": display_file_name, "fileSize": file_size,
                                              "unencryptedChecksum": check_sum}) )
            else:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )

        responses.add_callback(
            responses.GET,
            "https://ega.ebi.ac.uk:8052/elixir/data/metadata/files/{}".format(good_file_id),
            callback=request_callback,
            content_type='application/json',
        )

        rv = pyega3.get_file_name_size_md5(good_token, good_file_id)
        self.assertEqual( len(rv), 4 )
        self.assertEqual( rv[0], display_file_name )
        self.assertEqual( rv[1], file_name )
        self.assertEqual( rv[2], file_size )
        self.assertEqual( rv[3], check_sum )

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.get_file_name_size_md5(bad_token, good_file_id)

        bad_file_id = "EGAF00000000000"
        with self.assertRaises(requests.exceptions.ConnectionError):
            pyega3.get_file_name_size_md5(good_token, bad_file_id)

        bad_file_id_2 = "EGAF00000000666"
        responses.add(
            responses.GET,
            "https://ega.ebi.ac.uk:8052/elixir/data/metadata/files/{}".format(bad_file_id_2),
            json={"fileName": None, "displayFileName": None, "unencryptedChecksum": None}, status=200)
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
        fname_on_disk   = file_name + '-from-'+str(slice_start)+'-len-'+str(slice_length)+'.slice'
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
            with mock.patch("os.path.getsize", lambda path: self.written_bytes if path==fname_on_disk else 0):
                m_open().write.side_effect = mock_write
                pyega3.download_file_slice(good_url, good_token, file_name, slice_start, slice_length)
                self.assertEqual( slice_length, self.written_bytes )

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
        #merged_bytes.extend(files_to_merge['f1.bin'])
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
            with mock.patch( 'os.rename', lambda s,d: merged_bytes.extend(files_to_merge[os.path.basename(s)]) ):
                pyega3.merge_bin_files_on_disk( target_file_name, list(files_to_merge.keys()), 0) #this value can be changed from 0 to other/actual value

        mocked_remove.assert_has_calls( [mock.call(f) for f in list(files_to_merge.keys())[1:]] )

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
                fname = rand_str()
                with mock.patch('os.path.exists', lambda path:path==fname):
                    result = pyega3.md5(fname, len(fname))
                    self.assertEqual(md5, result)

    @responses.activate
    @mock.patch('os.remove')
    @mock.patch("time.sleep", lambda secs:None )
    @mock.patch("pyega3.pyega3.get_token", lambda creds: 'good_token' )
    def test_download_file(self,mocked_remove):
        pyega3.URL_API = 'https://ega.ebi.ac.uk:8052/elixir/data'
        pyega3.URL_API_TICKET = 'https://ega.ebi.ac.uk:8052/elixir/tickets/tickets'
        file_id = "EGAF00000000001"
        url     = "https://ega.ebi.ac.uk:8052/elixir/data/files/{}".format(file_id)
        good_creds={"username":rand_str(),"password":rand_str(),"client_secret":rand_str()}

        mem             = virtual_memory().available
        file_sz         = random.randint(1, mem//512)
        file_name       = "resulting.file"
        file_contents   = os.urandom(file_sz)
        file_md5        = hashlib.md5(file_contents).hexdigest()

        mocked_files = {}
        def open_wrapper(filename, mode):
            filename = os.path.basename(filename)
            if filename not in mocked_files :
                if 'r' in mode: raise Exception("Attempt to read mock file before it was created.")
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
            if auth_hdr is None or auth_hdr != 'Bearer ' + 'good_token':
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
                        with mock.patch( 'os.rename', lambda s,d: mocked_files.__setitem__(os.path.basename(d),mocked_files.pop(os.path.basename(s))) ):
                            pyega3.download_file_retry(
                                # add 16 bytes to file size ( IV adjustment )
                                good_creds, file_id, file_name, file_name+".cip", file_sz+16, file_md5, 1, None, output_file=None, genomic_range_args=None, max_retries=5, retry_wait=5 )
                            self.assertEqual( file_contents, mocked_files[file_name] )

                            # to cover 'local file exists' case
                            pyega3.download_file_retry(
                                good_creds, file_id, file_name, file_name+".cip", file_sz+16, file_md5, 1, None, output_file=None, genomic_range_args=None, max_retries=5, retry_wait=5 )

                            wrong_md5 = "wrong_md5_exactly_32_chars_longg"
                            with self.assertRaises(Exception):
                                pyega3.download_file_retry(
                                    good_creds, file_id, file_name, file_name+".cip", file_sz+16, wrong_md5, 1, None, output_file=None, genomic_range_args=None)

                            mocked_remove.assert_has_calls(
                                [ mock.call(os.path.join( os.getcwd(), file_id, os.path.basename(f) )) for f in list(mocked_files.keys()) if not file_name in f ],
                                any_order=True )

                            with mock.patch('htsget.get') as mocked_htsget:
                                pyega3.download_file_retry(
                                    good_creds, file_id, file_name, file_name+".cip", file_sz+16, file_md5, 1, None, output_file=None, genomic_range_args=("chr1",None,1,100,None), max_retries=5, retry_wait=5 )

                            args, kwargs = mocked_htsget.call_args
                            self.assertEqual(args[0], 'https://ega.ebi.ac.uk:8052/elixir/tickets/tickets/files/EGAF00000000001')

                            self.assertEqual(kwargs.get('reference_name'), 'chr1')
                            self.assertEqual(kwargs.get('reference_md5'), None)
                            self.assertEqual(kwargs.get('start'), 1)
                            self.assertEqual(kwargs.get('end'), 100)
                            self.assertEqual(kwargs.get('data_format'), None)

        with self.assertRaises(ValueError):
            pyega3.download_file_retry( "", "", "", "", 0, 0, 1, "key", output_file=None, genomic_range_args=None, max_retries=5, retry_wait=5 )

        pyega3.download_file_retry( "", "", "test.gz", "test.gz.gpg",  0, 0, 1, None, output_file=None, genomic_range_args=None, max_retries=5, retry_wait=5 )

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
                "unencryptedChecksum": file1_md5,
                "datasetId": good_dataset,
                "fileStatus": "available",
                "fileId": "EGAF00000000001",
                "checksumType": "MD5",
                "fileSize": file1_sz,
                "fileName": "EGAZ00000000001/ENCFF000001.bam.cip",
                "displayFileName": "ENCFF000001.bam.cip"
            },
            {
                "unencryptedChecksum": file2_md5,
                "datasetId": good_dataset,
                "fileStatus": "available",
                "fileId": "EGAF00000000002",
                "checksumType": "MD5",
                "fileSize": file2_sz,
                "fileName": "EGAZ00000000002/ENCFF000002.bam",
                "displayFileName": "ENCFF000002.bam.cip"
            } ]

        with mock.patch("pyega3.pyega3.get_token", lambda creds: 'token' ):
            with mock.patch("pyega3.pyega3.api_list_authorized_datasets", lambda token: [good_dataset]):
                with mock.patch("pyega3.pyega3.api_list_files_in_dataset", lambda token, dataset_id: files ):
                    creds={"username":rand_str(),"password":rand_str(),"client_secret":rand_str()}
                    num_connections = 1
                    bad_dataset = "EGAD00000000666"
                    pyega3.download_dataset( creds, bad_dataset, num_connections, None, None, None, 5,5 )
                    self.assertEqual( 0, mocked_dfr.call_count )

                    pyega3.download_dataset( creds, good_dataset, num_connections, None, None, None, 5,5 )
                    self.assertEqual( len(files)-1, mocked_dfr.call_count )

                    mocked_dfr.assert_has_calls(
                        [mock.call(creds, f['fileId'], f['displayFileName'], f['fileName'], f['fileSize'],f['unencryptedChecksum'],num_connections,None,None,None,5,5) for f in files if f["fileStatus"]=="available"] )

                    # files[1]["unencryptedChecksum"] = "wrong_md5_exactly_32_chars_longg"
                    def dfr_throws(p1,p2,p3,p4,p5,p6): raise Exception("bad MD5")
                    with mock.patch("pyega3.pyega3.download_file_retry", dfr_throws ):
                        pyega3.download_dataset( creds, good_dataset, num_connections, None, None, None, 5,5 )



    def test_generate_output_filename(self):
        folder = "FOO"
        file_id = "EGAF001"
        base_name = "filename"
        base_ext = ".ext"
        full_name = "/really/long/"+base_name+base_ext
        self.assertEqual(
            os.path.join(folder, file_id, base_name+base_ext),
            pyega3.generate_output_filename( folder, file_id, full_name , None )
        )
        folder = os.getcwd()
        self.assertEqual(
            os.path.join(folder, file_id, base_name+base_ext ),
            pyega3.generate_output_filename( folder, file_id, full_name , None )
        )
        self.assertEqual(
            os.path.join(folder, file_id, base_name+"_genomic_range_chr1_100_200"+base_ext+".cram" ),
            pyega3.generate_output_filename( folder, file_id, full_name , ( "chr1", None, 100, 200, "CRAM" ) )
        )

    def test_pretty_print_authorized_datasets(self):
        pyega3.pretty_print_authorized_datasets(['EGAD0123'])

    def test_pretty_print_files_in_dataset(self):
        testReply=  [{"checksumType": "MD5", "unencryptedChecksum": "MD5SUM678901234567890123456789012",
                      "fileName": "EGAZ00001314035.bam.bai.cip", "displayFileName": "EGAZ00001314035.bam.bai.cip", "fileStatus": "available",
                      "fileSize": 0, "datasetId": "EGAD00001003338", "fileId": "EGAF00001753747" }]
        pyega3.pretty_print_files_in_dataset(testReply, ['EGAD0123'])

    @mock.patch('getpass.getpass')
    def test_get_credential(self, getpw):
        user_input = ["U", "P"]
        getpw.return_value = user_input[1]
        with mock.patch('builtins.input', side_effect=user_input[0]):
            self.assertEqual(pyega3.get_credential(), (user_input[0],user_input[1], None))

    @mock.patch('getpass.getpass')
    def test_load_credential(self, getpw):
        user_input = ["U", "P"]
        getpw.return_value = user_input[1]
        with mock.patch('builtins.input', side_effect=user_input[0]):
            self.assertEqual(pyega3.load_credential("unknownfile.txt"), (user_input[0],user_input[1], None))

    def test_legacy_dataset(self):
        with self.assertRaises(SystemExit):
            pyega3.api_list_files_in_dataset("token", "EGAD00000000003")

        with self.assertRaises(SystemExit):
            pyega3.download_dataset("credentials", "EGAD00000000003", "1", "key", "output_dir", "genomic_range_args")

    def test_main(self):
        with self.assertRaises(SystemExit):
            pyega3.main()

    def test_load_server_config_invalidPath(self):
        with self.assertRaises(SystemExit):
            pyega3.load_server_config("/invalidpath");

    def test_load_server_config_invalidJson(self):
        with mock.patch('os.path.exists') as m:
            m.return_value = True
            with mock.patch( "builtins.open", mock.mock_open(read_data="bad json") ):
                with self.assertRaises(SystemExit):
                    bad_credentials_file = "bad_server_config.json"
                    pyega3.load_server_config(bad_credentials_file)

    def test_load_server_config_missingAttributesInJsonFile(self):
        with mock.patch('os.path.exists') as m:
            m.return_value = True
            good_server_config_file={"url_auth":rand_str(),"url_api":rand_str()}
            m_open = mock.mock_open(read_data=json.dumps(good_server_config_file))
            with mock.patch( "builtins.open", m_open ):
                with self.assertRaises(SystemExit):
                    good_server_config_file = "server.json"
                    pyega3.load_server_config(good_server_config_file)

    def test_temporary_files_are_not_deleted_if_the_user_says_so(self):
        # The user asks for keeping the temporary files:
        pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = False

        self.server_config_file_loaded_successfully()
        self.user_has_authenticated_successfully()

        output_file_path = self.create_output_file_path()
        expected_file_size = pyega3.DOWNLOAD_FILE_SLICE_CHUNK_SIZE * 3
        self.download_with_exception(output_file_path, expected_file_size)

        temp_file = pyega3.TEMPORARY_FILES.pop()
        # The temporary file should exist because the pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED
        # variable was set to False previously:
        self.assertTrue(os.path.exists(temp_file))

        temp_file_size = os.stat(temp_file).st_size
        # The download client should have been able to download the whole file:
        self.assertEqual(temp_file_size, expected_file_size - 3 * 1000)
        os.remove(temp_file)

        self.assertFalse(os.path.exists(output_file_path))

    def test_temporary_files_are_deleted_if_the_user_says_so(self):
        pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = True

        self.server_config_file_loaded_successfully()
        self.user_has_authenticated_successfully()

        output_file_path = self.create_output_file_path()
        expected_file_size = pyega3.DOWNLOAD_FILE_SLICE_CHUNK_SIZE * 3
        self.download_with_exception(output_file_path, expected_file_size)

        temp_file = pyega3.TEMPORARY_FILES.pop()
        # The temporary file should not exist because the pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED
        # variable was set to True previously:
        self.assertFalse(os.path.exists(temp_file))

        self.assertFalse(os.path.exists(output_file_path))

    @responses.activate
    def test_temp_files_are_deleted_automatically_if_there_are_no_exceptions(self):
        """
        The temporary files are deleted by the algorithm automatically, during the happy path,
        when the temporary files are assembled into the final, big file.
        There's no need for extra deleting-mechanism.
        """
        pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = False

        file_size_without_iv = 92700
        file_size_with_iv = file_size_without_iv + 16

        self.server_config_file_loaded_successfully()
        self.user_has_authenticated_successfully()

        input_file = bytearray(os.urandom(file_size_without_iv))
        self.file_can_be_downloaded(input_file)

        output_file_path = self.create_output_file_path()

        pyega3.download_file_retry(('', ''), 'test_file_id1', output_file_path, output_file_path,
                                        file_size_with_iv, 'check_sum', 1, None, output_file_path, None, 2, 0.1)

        temp_file = pyega3.TEMPORARY_FILES.pop()
        # The temporary file should not exist because everything went fine,
        # and it was deleted automatically:
        self.assertFalse(os.path.exists(temp_file))

        self.assertTrue(os.path.exists(output_file_path))
        output_file_size = os.stat(output_file_path).st_size
        self.assertEqual(output_file_size, file_size_without_iv)
        os.remove(output_file_path)

    @responses.activate
    def test_second_attempt_succeeds(self):
        """
        It was not possible to download the whole file on the first download attempt,
        so the script retries for a second time and continues from where it stopped
        on the first attempt.
        """

        pyega3.TEMPORARY_FILES_SHOULD_BE_DELETED = False

        file_size_without_iv = 92700
        file_size_with_iv = file_size_without_iv + 16

        self.server_config_file_loaded_successfully()
        self.user_has_authenticated_successfully()

        amount_of_missing_bytes = 123
        file_size_with_missing_bytes = file_size_without_iv - amount_of_missing_bytes
        input_file_with_few_bytes_missing = bytearray(os.urandom(file_size_with_missing_bytes))
        self.file_can_be_downloaded(input_file_with_few_bytes_missing)

        rest_of_the_input_file = bytearray(os.urandom(amount_of_missing_bytes))
        self.file_can_be_downloaded(rest_of_the_input_file)

        output_file_path = self.create_output_file_path()

        pyega3.download_file_retry(('', ''), 'test_file_id1', output_file_path, output_file_path,
                                   file_size_with_iv, 'check_sum', 1, None, output_file_path, None, 2, 0.1)

        temp_file = pyega3.TEMPORARY_FILES.pop()
        # The temporary file should not exist because everything went fine,
        # and it was deleted automatically:
        self.assertFalse(os.path.exists(temp_file))

        self.assertEqual(responses.calls[1].request.headers.get('Range'), 'bytes=0-92699')
        self.assertEqual(responses.calls[2].request.headers.get('Range'), 'bytes=92577-92699')
        self.assertEqual(responses.calls[2].request.headers.get('Range'), 'bytes={}-92699'
                         .format(file_size_with_missing_bytes))

        self.assertTrue(os.path.exists(output_file_path))
        output_file_size = os.stat(output_file_path).st_size
        self.assertEqual(output_file_size, file_size_without_iv)
        os.remove(output_file_path)

    def test_deleting_non_existent_file_does_not_raise_exception(self):
        non_existent_file = '/tmp/non/existent/file'
        self.assertFalse(os.path.exists(non_existent_file))

        # No exception is raised:
        pyega3.delete_temporary_files([non_existent_file])

    def test_calculating_md5_of_non_existent_file_raises_exception(self):
        non_existent_file = '/tmp/non/existent/file'
        self.assertFalse(os.path.exists(non_existent_file))

        with self.assertRaises(Exception):
            pyega3.calculate_md5(non_existent_file, -1)

    @responses.activate
    def download_with_exception(self, output_file_path, expected_file_size):
        """
        Simulates downloading a file of the given size: "true_file_size".
        During the transfer, an exception happens and the temporary file is either deleted
        or kept, depending on the TEMPORARY_FILES_SHOULD_BE_DELETED flag.
        """

        number_of_retries = 2
        not_enough_bytes = int(expected_file_size / 3 - 1000)

        # First, normal GET request:
        self.file_can_be_downloaded(self.create_input_file(not_enough_bytes))
        # First retry attempt:
        self.file_can_be_downloaded(self.create_input_file(not_enough_bytes))
        # Second, last retry attempt:
        self.file_can_be_downloaded(self.create_input_file(not_enough_bytes))

        with self.assertRaises(Exception) as context_manager:
            pyega3.download_file_retry(('', ''), 'test_file_id1', output_file_path, output_file_path,
                                            expected_file_size, 'check_sum', 1, None, output_file_path, None,
                                            number_of_retries, 0.1)

        exception_message = str(context_manager.exception)
        self.assertRegex(exception_message, r'Slice error: received=\d+, requested=\d+')

        self.assertFalse(os.path.exists(output_file_path))

    @staticmethod
    def server_config_file_loaded_successfully():
        pyega3.URL_AUTH = 'https://test.ebi.ac.uk/ega-openid-connect-server/token'
        pyega3.URL_API = 'https://test.ebi.ac.uk/elixir/data'
        pyega3.URL_API_TICKET = 'https://test.ebi.ac.uk/elixir/tickets/tickets',
        pyega3.CLIENT_SECRET = 'test-client-secret'

    @staticmethod
    def user_has_authenticated_successfully(access_token_response='test_access_token1'):
        responses.add(responses.POST,
                      re.compile(r'.+/ega-openid-connect-server/token$'),
                      json={'access_token': access_token_response},
                      status=200)

    @staticmethod
    def file_can_be_downloaded(input_file, file_id='test_file_id1'):
        responses.add(responses.GET,
                      re.compile(r'.+/files/{}\?destinationFormat=plain$'.format(file_id)),
                      body=input_file,
                      status=200)

    @staticmethod
    def user_can_list_datasets(datasets=None):
        if datasets is None:
            datasets = ['test_dataset1']

        responses.add(responses.GET,
                      re.compile(r'.+/metadata/datasets$'),
                      # json={'datasets': datasets},
                      json=datasets,
                      status=200)

    @staticmethod
    def user_can_list_files_in_dataset(dataset, files_response=None):
        if files_response is None:
            file_response = {
                'fileStatus': 'available',
                'fileId': 'test_fileId1',
                'fileName': 'test_fileName1',
                'displayFileName': 'test_displayFileName1',
                'fileSize': 123,
                'unencryptedChecksum': 'test_unencryptedChecksum1'
            }
            files_response = [file_response]

            responses.add(responses.GET,
                          re.compile(r'.+/metadata/datasets/{}/files$'.format(dataset)),
                          json=files_response,
                          status=200)

    @staticmethod
    def user_can_access_file_metadata(file_id, file_response=None):
        if file_response is None:
            file_response = {
                'displayFileName': 'test_displayFileName1',
                'fileName': 'test_fileName1',
                'fileSize': 123,
                'unencryptedChecksum': 'test_unencryptedChecksum1'
            }

            responses.add(responses.GET,
                          re.compile(r'.+/metadata/files/{}$'.format(file_id)),
                          json=file_response,
                          status=200)

    @staticmethod
    def user_can_access_dataset(dataset):
        Pyega3Test.user_can_list_datasets([dataset])

    @staticmethod
    def create_input_file(file_size):
        return bytearray(os.urandom(file_size))

    @staticmethod
    def create_output_file_path():
        """Returns a file-path to a random, temporary file-name."""
        _, output_file_path = tempfile.mkstemp()
        os.remove(output_file_path)
        return output_file_path


if __name__ == '__main__':
    del(sys.argv[1:])
    unittest.main(exit=False)
