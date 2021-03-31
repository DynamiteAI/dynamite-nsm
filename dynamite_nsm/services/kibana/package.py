import logging
import mimetypes
import tarfile
from getpass import getpass
from io import BytesIO, IOBase
from typing import AnyStr, Optional, Tuple, IO

import requests

from dynamite_nsm.logger import get_logger
from dynamite_nsm.utilities import get_primary_ip_address


class SavedObjectsManager(object):
    def __init__(self,
                 stdout: Optional[bool] = True,
                 verbose: Optional[bool] = False):
        """
        :param name: The name of the package you wish to install
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """
        self._api_auth_token = None
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger(str('KIBANA.PACKAGE_MANAGER'), level=log_level, stdout=stdout)

    @property
    def kibana_url(self):
        return f'http://{get_primary_ip_address()}:5601'

    @staticmethod
    def _get_kibana_auth_securely(username: Optional[str] = None, password: Optional[str] = None) -> Tuple[str, str]:
        # need to be able to provide these as parameters to the cmd
        if not username:
            print()
            username = input("Kibana Username: ")
        if not password:
            print()
            password = getpass("Kibana Password: ")
        return username, password

    def browse_saved_objects(self, username: Optional[str] = None, password: Optional[str] = None,
                             saved_object_type: Optional[str] = None) -> requests.Response:
        auth = self._get_kibana_auth_securely(username, password)
        if saved_object_type:
            resp = requests.get(f'{self.kibana_url}/api/saved_objects/_find?type={saved_object_type}', auth=auth)
        resp = requests.get(
            f'{self.kibana_url}/api/saved_objects/_find'
            f'?type=dashboard'
            f'&type=index-pattern'
            f'&type=visualization'
            f'&type=search'
            f'&type=config'
            f'&type=timelion-sheet',
            auth=auth)
        if resp.status_code not in range(200, 299):
            self.logger.error(f'Kibana endpoint returned a {resp.status_code} - {resp.text}')
            # TODO raise exception
        return resp

    def import_kibana_saved_objects(self, username: str, password: str, kibana_objects_file: IO[AnyStr],
                                    space: Optional[str] = None, overwrite: Optional[bool] = False,
                                    create_copies: Optional[bool] = True):

        auth = self._get_kibana_auth_securely(username, password)

        if space:
            url = f'{self.kibana_url}/s/{space}/api/saved_objects/_import'
        else:
            url = f'{self.kibana_url}/api/saved_objects/_import'
        if all([overwrite, create_copies]):
            raise ValueError("createNewCopies and overwrite cannot be used together.")

        # TODO: expose these as params when args work
        params = {'overwrite': overwrite, 'createNewCopies': create_copies}

        # TODO: Catch connection denied when kibana is down and handle/inform user gracefully
        if isinstance(kibana_objects_file, IOBase):
            reqdata = {'file': ('dynamite_import.ndjson', kibana_objects_file)}
        else:
            reqdata = {'file': kibana_objects_file}
        resp = requests.post(url, params=params, auth=auth, files=reqdata, headers={'kbn-xsrf': 'true'})
        if resp.status_code not in range(200, 299):
            self.logger.error(f'Kibana endpoint returned a {resp.status_code} - {resp.text}')
            # TODO raise exception
        return resp.json()

    def install(self, package_install_path: str, username: Optional[str] = None, password: Optional[str] = None):
        """
        Install a package. A package can be given as an archive or directory. A package must contain one or more ndjson
        files and a manifest.json file

        :param package_install_path: The path to the package to install
        :param username: The name of the Kibana user to authenticate with
        :param password: The corresponding Kibana password
        """

        # check mimetype of the file to determine how to proceed

        filetype, encoding = mimetypes.MimeTypes().guess_type(package_install_path)
        if filetype == 'application/x-tar' or encoding == 'gzip':
            # handle tarfile
            tar = tarfile.open(package_install_path)
            for member in tar:
                # should we validate the json before sending it up to kibana?
                # TODO: Check folders recursively
                kibana_objects_file = BytesIO(tar.extractfile(member).read())
                self.import_kibana_saved_objects(username=username, password=password,
                                                 kibana_objects_file=kibana_objects_file)
                kibana_objects_file.close()

        elif filetype in ('application/json', 'text/plain') or any(
                [package_install_path.endswith('.ndjson'), package_install_path.endswith('json')]):
            with open(package_install_path, 'r') as kibana_objects_file:
                self.import_kibana_saved_objects(username=username, password=password,
                                                 kibana_objects_file=kibana_objects_file)
        else:
            self.logger.error("Files must be one of: .ndjson, .json, .tar.xz, .tar.gz")
            # TODO raise exception

    def list(self, username: Optional[str] = None, password: Optional[str] = None):
        """
        List packages currently installed for this instance
        """
        raise NotImplementedError()

    def list_saved_objects(self, username: Optional[str] = None, password: Optional[str] = None,
                           saved_object_type: Optional[str] = None):
        """
        List the saved_objects currently installed irrespective of which "package" the belong too

        :param username: The name of the Kibana user to authenticate with
        :param password: The corresponding Kibana password
        :param saved_object_type: One of the following supported saved_object types:
                            ['config', 'dashboard', 'index-pattern', 'search', 'timelion-sheet', 'visualization']
        """

        username, password = auth = self._get_kibana_auth_securely(username, password)
        fetched_data = self.browse_saved_objects(username, password, saved_object_type=saved_object_type).json()
        for obj in fetched_data.get('saved_objects', []):
            kibana_object_id = obj['id']
            kibana_object_type = obj['type']
            kibana_object_title = obj['attributes'].get('title', '')
            item = f'[{kibana_object_type}][{kibana_object_id}] {kibana_object_title}'
            print(item)

    def uninstall(self):
        raise NotImplementedError()
