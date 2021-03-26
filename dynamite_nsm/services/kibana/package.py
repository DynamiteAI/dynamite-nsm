import os
import logging
import requests
from typing import Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.kibana import config
from typing import Dict, Optional, Union
from getpass import getpass
from dynamite_nsm.utilities import get_primary_ip_address


class SavedObjectsManager(object):
    def __init__(self, name: Optional[str] = "package.saved_objects", verbose: Optional[bool] = False):
        self._api_auth_token = None
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger(str(name).upper(), level=log_level, stdout=True)

            
    @property
    def kibana_url(self):
        return f'http://{get_primary_ip_address()}:5601'

    def _get_kibana_auth(self):
        # need to be able to provide these as parameters to the cmd
        username = input("\nKibana Username: ")
        password = getpass("Kibana Password:\n")
        return (username,password)


    def browse_saved_objects(self, type, auth):
        return requests.get(f'{self.kibana_url}/api/saved_objects/_find?type={type}', auth=auth)
        
    def import_saved_objects(self, auth, file, space=None, overwrite=False, create_copies=True):
        if space:
            url = f'{self.kibana_url}/s/{space}/api/saved_objects/_import'
        else:
            url = f'{self.kibana_url}/api/saved_objects/_import'
        if all([overwrite, create_copies]):
            raise ValueError("createNewCopies and overwrite cannot be used together.")
        
        #TODO: expose these as params when args work
        params = {'overwrite': overwrite, 'createNewCopies': create_copies}

        # TODO: Catch connection denied when kibana is down and handle/inform user gracefully
        reqdata = {'file': file}
        resp = requests.post(url, params=params, auth=auth, files=reqdata, headers={'kbn-xsrf': 'true'})

        if resp.status_code == 401:
            print("Problem authenticating to Kibana, invalid username/password?")
        if resp.status_code in [400, 500]:
            print("Something went wrong trying to import the saved object(s):")
            print(resp.json())
        return resp.json()

        
    
    def add(self):
        # TODO: figure out why args to params is not working

        #needs to be available as a parameter
        file = None
        while not bool(file):
            file = input("Path To ndjson file: ")
            abspath = f'{os.getcwd()}/{file}'
            if file and not os.path.isfile(abspath):
                print(f'could not find file: {abspath}')
                file = None
        with open(abspath, 'r') as ndjsonfile:
            print(ndjsonfile.name)
            print(self.import_saved_objects(self._get_kibana_auth(), ndjsonfile))
        





    def list(self):
        # TODO: figure out why args to params is not working
        selection = None
        types = ['visualization', 'dashboard', 'search', 'index-pattern', 'config', 'timelion-sheet']
        print("Available saved object types:")
        for type in types:
            print(f"{types.index(type) + 1} {type}")
        while selection is None:
            sel = input("Select saved object type: ")
            if sel in [str(i) for i in range(1,len(types)+1)]:
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

