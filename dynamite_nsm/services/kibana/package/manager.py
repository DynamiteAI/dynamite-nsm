import logging
import mimetypes
import tarfile
import os
import json
import requests
from getpass import getpass
from io import BytesIO, IOBase
from typing import AnyStr, Optional, Tuple, IO
from dynamite_nsm.logger import get_logger
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.services.kibana.package.mappings import PACKAGES_INDEX_MAPPING, PACKAGES_INDEX_NAME
from dynamite_nsm.services.kibana.package.schemas import InstalledPackagesListSchema, \
                                                         InstalledObjectSchema, \
                                                         PackageManifestSchema, \
                                                         SchemaToObject



class InstalledObject(SchemaToObject):
    def __init__(self, json_data):
        super().__init__(json_data, InstalledObjectSchema())

    def __repr__(self) -> str:
        return f"<InstalledObect id: {self.id}, tile: {self.title}, package: {self.package_slug} >"

class PackageManifest(SchemaToObject):
    def __init__(self, json_data):
        """
        :param json_data: JSON Body of the package manifest, conforms to PackageManifestSchema
        """
        super().__init__(json_data, PackageManifestSchema())

    def __repr__(self) -> str:
        return f"<PackageManifest(name={self.name}, author={self.author})>"

class InstalledPackages(object):

    def __init__(self, auth=None) -> None:
        self.package_index_name = PACKAGES_INDEX_NAME
        self.es_url = f'https://{get_primary_ip_address()}:9200'
        # should this be parameterized? its hardcoded in ES post install steps.
        self.auth = auth or ('admin', 'admin') 

    def _check_index_exists(self):
        res = requests.head(f"{self.es_url}/{self.package_index_name}", verify=False, auth=self.auth)
        return res.status_code == 200
    
    def create_packages_index(self):
        exists = self._check_index_exists()
        if not exists:
            res = requests.put(
                    url=f"{self.es_url}/{self.package_index_name}",
                    data=json.dumps(PACKAGES_INDEX_MAPPING),
                    auth=self.auth,
                    headers={'content-type': 'application/json'},
                    verify=False
                )
            return res.status_code == 200
        return True


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
        self.verbose = verbose
        self._installed_packages = None


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

    def _process_package_installation_results(self, kibana_response: dict) -> bool:
        success = kibana_response.get('success', False)
        errors = kibana_response.get('errors')
        if errors:
            for error in errors:
                print(f"{error['title']} - {error.get('error', {'type': 'unknown'})['type']}")
                if self.verbose:
                    print(f"{error}\n")
        for installed in kibana_response.get('successResults', []):
            if self.verbose:
                print(installed)
            # TODO: save to ES with package information using InstalledPackages


        return success

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
                                    space: Optional[str] = None, overwrite: Optional[bool] = True,
                                    create_copies: Optional[bool] = False):

        auth = self._get_kibana_auth_securely(username, password)

        if space:
            url = f'{self.kibana_url}/s/{space}/api/saved_objects/_import'
        else:
            url = f'{self.kibana_url}/api/saved_objects/_import'
        if all([overwrite, create_copies]):
            raise ValueError("createNewCopies and overwrite cannot be used together.")

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
        installation_statuses = []
        package_name = "Package"
        if filetype == 'application/x-tar' or encoding == 'gzip':
            # handle tarfile
            tar = tarfile.open(package_install_path)
            try:
                manifest = tar.extractfile('manifest.json')
                manifest = PackageManifest(manifest.read().decode('utf8'))
                package_name = manifest.name
            except KeyError:
                print("Package must contain a manifest.json")
                exit(0)
            for member in manifest.file_list:
                # should we validate the json before sending it up to kibana?
                kibana_objects_file = BytesIO(tar.extractfile(member).read())
                result = self.import_kibana_saved_objects(username=username, password=password,
                                                 kibana_objects_file=kibana_objects_file)
                kibana_objects_file.close()
                installation_statuses.append(self._process_package_installation_results(result))
        # Should we remove this and ONLY install validatable packages?
        elif filetype in ('application/json', 'text/plain') or any(
                [package_install_path.endswith('.ndjson'), package_install_path.endswith('json')]):
            with open(package_install_path, 'r') as kibana_objects_file:
                result = self.import_kibana_saved_objects(username=username, password=password,
                                                 kibana_objects_file=kibana_objects_file)
                installation_statuses.append(self._process_package_installation_results(result))
        else:
            self.logger.error("Files must be one of: .ndjson, .json, .tar.xz, .tar.gz")
            # TODO raise exception
        
        if not all(installation_statuses):
            print(f"\r\n{package_name} installation failed.")
            if not self.verbose:
                print("Use --verbose flag to see more error detail.\n")
        else:
            print(f"\r\n{package_name} installation succeeded!")

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
