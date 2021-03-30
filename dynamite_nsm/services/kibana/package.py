import logging
import os
import tarfile
import zipfile
import mimetypes
from getpass import getpass
from typing import Optional

import requests

from dynamite_nsm.logger import get_logger
from dynamite_nsm.utilities import get_primary_ip_address
from io import StringIO, BytesIO

class SavedObjectsManager(object):
    def __init__(self, name: Optional[str] = "package.saved_objects",
                 stdout: Optional[bool] = True,
                 verbose: Optional[bool] = False,
                 file: Optional[str] = ""):
        """
        :param name: The name of the package you wish to install
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """
        self._api_auth_token = None
        self.file = file
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger(str(name).upper(), level=log_level, stdout=stdout)

    @property
    def kibana_url(self):
        return f'http://{get_primary_ip_address()}:5601'

    def _get_kibana_auth(self):
        # need to be able to provide these as parameters to the cmd
        username = input("\nKibana Username: ")
        password = getpass("Kibana Password:\n")
        return (username, password)

    def browse_saved_objects(self, type, auth):
        return requests.get(f'{self.kibana_url}/api/saved_objects/_find?type={type}', auth=auth)

    def import_saved_objects(self, auth, file, space=None, overwrite=False, create_copies=True):
        if space:
            url = f'{self.kibana_url}/s/{space}/api/saved_objects/_import'
        else:
            url = f'{self.kibana_url}/api/saved_objects/_import'
        if all([overwrite, create_copies]):
            raise ValueError("createNewCopies and overwrite cannot be used together.")

        # TODO: expose these as params when args work
        params = {'overwrite': overwrite, 'createNewCopies': create_copies}

        # TODO: Catch connection denied when kibana is down and handle/inform user gracefully
        if type(file) in (StringIO, BytesIO):
            reqdata = {'file': ('dynamite_import.ndjson', file)}
        else:
            reqdata = {'file': file}
        resp = requests.post(url, params=params, auth=auth, files=reqdata, headers={'kbn-xsrf': 'true'})
        if resp.status_code == 401:
            print("Problem authenticating to Kibana, invalid username/password?")
        if resp.status_code in [400, 500]:
            print("Something went wrong trying to import the saved object(s):")
            print(resp.json())
        return resp.json()

    def add(self):
        def _get_install_file_abs_path(file):
            if file:
                abspath = f'{os.getcwd()}/{file}'
                if not os.path.isfile(abspath):
                    print(f'could not find file: {abspath}')
                    return None
            return abspath
        def _open_and_import_ndjsonfile(file_object):
            # TODO: Better output w/ num successful imports, titles, etc
            print(self.import_saved_objects(self._get_kibana_auth(), file_object))
            if not file_object.closed:
                file_object.close()
            
        # needs to be available as a parameter
        if self.file:
            abspath = _get_install_file_abs_path(self.file)
        else:
            while not bool(self.file):
                file = input("Path To ndjson file, folder or archive: ")
                abspath = _get_install_file_abs_path(file)
                if not abspath:
                    self.file = None
        # check mimetype of the file to determine how to proceed
        filetype, encoding = mimetypes.MimeTypes().guess_type(abspath)
        if filetype == 'application/x-tar' or encoding == 'gzip':
            #handle tarfile
            tar = tarfile.open(abspath)
            for member in tar:
                #should we validate the json before sending it up to kibana?
                # TODO: Check folders recursively
                file = BytesIO(tar.extractfile(member).read())
                _open_and_import_ndjsonfile(file)

            pass
        elif filetype in ('application/json', 'text/plain') or any([abspath.endswith('.ndjson'), abspath.endswith('json')]):
            with open(abspath, 'r') as ndjsonfile:
                _open_and_import_ndjsonfile(ndjsonfile)
        else:
            print("Files must be one of: .ndjson, .json, .tar.xz, .tar.gz")

    def list(self):
        # TODO: figure out why args to params is not working
        selection = None
        types = ['visualization', 'dashboard', 'search', 'index-pattern', 'config', 'timelion-sheet']
        print("Available saved object types:")
        for type in types:
            print(f"{types.index(type) + 1} {type}")
        while selection is None:
            sel = input("Select saved object type: ")
            if sel in [str(i) for i in range(1, len(types) + 1)]:
                selection = int(sel) - 1
            else:
                print("Invalid Selection")
        username, password = self._get_kibana_auth()
        fetched_data = self.browse_saved_objects(type=types[selection], auth=(username, password)).json()
        if types[selection] in ['dashboard', 'visualization', 'dashboard', 'search']:
            for obj in fetched_data.get('saved_objects', []):
                title = obj['attributes']['title']
                desc = obj.get('attributes').get('description', '')
                item = f'{title} - {desc}' if desc else title
                print(item)
        else:
            raise NotImplementedError()

    def remove(self):
        pass
