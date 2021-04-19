import logging
import mimetypes
import tarfile
import json
import re
import requests
from getpass import getpass
from collections import defaultdict
from uuid import uuid4
from unidecode import unidecode
from io import BytesIO, IOBase
from typing import AnyStr, Optional, Tuple, IO, List
from dynamite_nsm.logger import get_logger
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.utilities import PrintDecorations as PD
from dynamite_nsm.services.kibana.package.mappings import PACKAGES_INDEX_MAPPING, PACKAGES_INDEX_NAME
from dynamite_nsm.services.kibana.package.schemas import ORPHAN_OBJECT_PACKAGE_MANIFEST_DATA as OrphanPackageData, \
                                                         InstalledObjectSchema, \
                                                         PackageManifestSchema, \
                                                         SchemaToObject

class InstalledObject(SchemaToObject):
    def __init__(self, json_data):
        super().__init__(json_data, InstalledObjectSchema())

    @staticmethod
    def from_kwargs(**kwargs):
        data = {}
        data['title'] = kwargs.get('title')
        data['object_type'] = kwargs.get('object_type', None)
        data['object_id'] = kwargs.get('object_id', None)
        data['space_id'] = kwargs.get('space_id', None)
        obj = InstalledObject(data)
        return obj

    @staticmethod
    def from_installation_result(responsedata, **kwargs):
        data = {}
        data['title'] = responsedata.get('meta', {'title': 'untitled object'}).get('title')
        data['object_type'] = responsedata.get('type', None)
        # this is the id of the saved object, not the document for tracking
        data['object_id'] = responsedata.get('id', None)
        data.update(kwargs)
        obj = InstalledObject.from_kwargs(**data)
        return obj

    def __repr__(self) -> str:
        return f"<InstalledObect id: {self.object_id}, title: {self.title} >"

class PackageManifest(SchemaToObject):
    def __init__(self, json_data):
        """
        :param json_data: JSON Body of the package manifest, conforms to PackageManifestSchema
        """
        super().__init__(json_data, PackageManifestSchema())
        self.data['slug'] = self.create_slug()

    def create_slug(self):
        name = self.name or OrphanPackageData.get('name')
        # using unidecode to support unicode/ascii in the package manifest data.
        slug = unidecode(name).lower()
        return re.sub(r'[\W_]+', '-', slug)
    
    def json(self) -> str:
        if not self.data.get('slug', None):
            self.data['slug'] = self.slug
        return json.dumps(self.data)

    def __repr__(self) -> str:
        return f"<PackageManifest(name={self.name}, author={self.author})>"

class Package(object):

    package_index_name = PACKAGES_INDEX_NAME
    es_url = f'https://{get_primary_ip_address()}:9200'
    auth = ('admin', 'admin')
    _installed_objects = []
    
    def __init__(self, manifest: PackageManifest,
                       installed_objects = None,
                       auth: Optional[str] = None,
                       id: Optional[str] = None) -> None:
        self.manifest = manifest
        if installed_objects:
            self._installed_objects = installed_objects
        self.id = id
        self.auth = auth or Package.auth
        self.slug = self.manifest.create_slug()

    @staticmethod
    def es_search(query):
        result = requests.get(f"{Package.es_url}/{Package.package_index_name}/_search/",
                      json=query,
                      verify=False,
                      auth=Package.auth)
        if result.status_code not in range(200,299):
            raise ValueError(f"Failed to fetch package data")
        num_returned = result.json().get('hits', {
            "total" : {
                "value" : 0,
            },
            "hits" : []
        }).get('total').get('value')

        if not num_returned:
             return None
        return result.json()

    def reload_installed_objects(self):
        """
            Fetches Package information from  ES
            matching the existing package manifest
            and loads all installed objects 
            into self._installed_objects
        """
        # should we instead perform inner hits query on nested object to get objects for current slug?
        query = {
            "query": {
                "match":{
                    "manifest.slug":{
                        "query": self.slug,
                        "minimum_should_match": 1
                    }
                }
            }
        }
        
        result = Package.es_search(query)
        if not result:
            return []
        packagesdata = [r['_source'] for r in result['hits']['hits']]
        pkg = packagesdata[0]
        manifest = PackageManifest(pkg.get('manifest'))
        instobjs = [InstalledObject.from_kwargs(**iobj) for iobj in pkg.get('installed_objects')]
        self._installed_objects = instobjs
        return self._installed_objects
        

        
    @property
    def installed_objects(self):
        if not self._installed_objects:
            self.reload_installed_objects()
        return self._installed_objects

    def _check_index_exists(self):
        res = requests.head(f"{self.es_url}/{self.package_index_name}", verify=False, auth=self.auth)
        return res.status_code == 200

    @staticmethod
    def load_from_archive(package_path):
        tar = tarfile.open(package_path)
        try:
            manifest = tar.extractfile('manifest.json')
            manifest = PackageManifest(manifest.read().decode('utf8'))
            package = Package(manifest)
            return package
        except KeyError:
            print("Package must contain a manifest.json")


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
    
    @property
    def __dict__(self) -> dict:

        package_dict = {
            'id': self.id,
            'manifest': self.manifest.data or {},
            'installed_objects': [obj.data for obj in self.installed_objects]
        }
        return package_dict

    def es_input(self, **kwargs) -> dict:
        """
            friendly func name for __dict__
        """
        if self.id is None and 'id' not in kwargs:
            raise ValueError("An ID must be supplied before saving to ElasticSearch")
        inputdict = self.__dict__
        overrides = inputdict.keys()
        for arg, val in kwargs.items():
            if arg in overrides:
                inputdict[arg] = val
        return inputdict

    def result_to_object(self, result: dict, space_id: Optional[str] = None) -> InstalledObject:
        obj = InstalledObject.from_installation_result(result, space_id=space_id)
        if space_id:
            obj.space_id = space_id
        return obj
    
    def uninstall(self, kibana_url: str, auth: Tuple[str], force: Optional[bool] = False) -> bool:
        """[summary]

        Args:
            kibana_url (str): url for kibana
            auth (Tuple[str]): Authentication for kibana
            force (Optional[bool], optional): If True, objects with matching ID is uninstalled from all spaces. Defaults to True.

        Returns:
            bool: success
        """
        statuses = []
        for iobj in self.installed_objects:
            
            if iobj.space_id:
                if not force:
                    force = input(f"{iobj.title} was installed to a space. Do you want to remove it from all spaces? [y/n]") in "yY"
                url = f'{kibana_url}/s/{iobj.space_id}/api/saved_objects'
            else:
                force = True
                url = f'{kibana_url}/api/saved_objects'
            delurl = f"{url}/{iobj.object_type}/{iobj.object_id}"
            if force:
                delurl += "?force=true"
            resp = requests.delete(delurl, auth=auth, verify=False, headers={'kbn-xsrf': 'true'})
            success = resp.status_code in range(200,299)
            if success:
                self.deregister()
            statuses.append(success)
        return all(statuses)
        
    def deregister(self) -> bool:
        """
        Deregisters a package from the dynamite-packages index

        Returns:
            bool: success
        """
        exists = self._check_index_exists()
        if not exists:
            # Should this throw an error?
            return False
        res = requests.delete(f"{self.es_url}/{self.package_index_name}/_doc/{self.id}",
                      verify=False,
                      auth=self.auth,
                      headers={'kbn-xsrf': 'true'})
        return res.status_code in range(200, 299)

    def register(self) -> bool:
        """
        Registers a package in the dynamite-packages index

        Returns:
            bool: success
        """
        self.create_packages_index()
        id = uuid4()
        res = requests.post(f"{self.es_url}/{self.package_index_name}/_doc/{id}",
                      json=self.es_input(id=str(id)),
                      verify=False,
                      auth=self.auth)
        return res.status_code in range(200, 299)
    
    @staticmethod
    def find_by_id(package_id: str):
        """[summary]

        Args:
            package_id (str): uuid for package (source id, not document id.)

        Raises:
            ValueError: Something went wrong performing search. e.g: ES is down

        """
        query = {
            "query": {
                "match":{
                    "id":{
                        "query": package_id,
                        "minimum_should_match": 1
                    }
                }
            }
        }
        
        result = Package.es_search(query)
        if not result:
            return None
        packagesdata = [r['_source'] for r in result['hits']['hits']]
        pkg = packagesdata[0]
        manifest = PackageManifest(pkg.get('manifest'))
        instobjs = [InstalledObject.from_kwargs(**iobj) for iobj in pkg.get('installed_objects')]
        package = Package(manifest, instobjs, id=pkg.get('id'))
        return package


    @staticmethod
    def find_by_slug(package_slug: str):
        """

        Args:
            package_slug (str): slug for package

        Raises:
            ValueError: Something went wrong performing search. e.g: ES is down

        """
        query = {
            "query": {
                "match":{
                    "manifest.slug":{
                        "query": package_slug,
                        "minimum_should_match": 1
                    }
                }
            }
        }
        
        result = Package.es_search(query)
        if not result:
            return None
        packagesdata = [r['_source'] for r in result['hits']['hits']]
        pkg = packagesdata[0]
        manifest = PackageManifest(pkg.get('manifest'))
        instobjs = [InstalledObject.from_kwargs(**iobj) for iobj in pkg.get('installed_objects')]
        package = Package(manifest, instobjs, id=pkg.get('id'))
        return package

    @staticmethod
    def search_installed_packages(package_name=None) -> list:
        """
        Returns Packages with wildcard search on provided package name string,
            returns all packages if package name not supplied

        Args:
            package_name ([str], optional): UUID of the package. Defaults to None.


        Returns:
            list: List of Packages
        """
        query = {
            "aggs":{
                "manifest.name": {
                    "terms": {
                        "field": "manifest.name.keyword"
                    }
                }
            }
        }

        if package_name:
            query["query"] = {
                "wildcard":{
                    "package_name":{
                        "wildcard": f"*{package_name}*",
                    }
                }
            }

        result = Package.es_search(query)
        if not result:
            return None
        
        # If we want to just display the titles and num packages, we can pull from aggs result instead.
        packagesdata = [r['_source'] for r in result['hits']['hits']]
        packages = []
        for pkg in packagesdata:
            manifest = PackageManifest(pkg.get('manifest'))
            instobjs = [InstalledObject.from_kwargs(**iobj) for iobj in pkg.get('installed_objects')]
            package = Package(manifest, instobjs, id=pkg.get('id'))
            packages.append(package)
        return packages

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

    def _process_package_installation_results(self, package: Package, kibana_response: dict) -> bool:
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
            installed_obj = package.result_to_object(installed)
            package.installed_objects.append(installed_obj)
        return success

    def _select_packages_for_uninstall(self, package_name):
        INVALID_SELECTION = "Not a valid selection"
        NONINT_SELECTION = "Selections must be integers"
        print("\n\nSelect a package to uninstall:")
        installed_packages = Package.search_installed_packages(package_name)
        for package in installed_packages:
            idx = installed_packages.index(package)
            if package.manifest.description and len(package.manifest.description) > 50:
                desc = f"{package.manifest.description[:50]}.."
            else:
                desc = package.manifest.description
            lbb = PD.colorize('[', 'bold')
            rbb = PD.colorize(']', 'bold')
            packagename = PD.colorize(package.manifest.name, 'bold')
            packageline = f"{lbb}{idx+1}{rbb} {packagename}\n{' ' * (len(str(idx)) + 2)} - {desc}"
            print(packageline)
        print()
        selections = []
        while not bool(selections):
            _selections = input("Select package(s) to uninstall:\r\n")
            _selections = _selections.split(" ")
            try:
                for sel in _selections:
                    sel = int(sel)
                    if sel-1 not in range(0, len(installed_packages)):
                        raise ValueError(INVALID_SELECTION)
                    selections.append(sel)
            except ValueError as e:
                if str(e) == INVALID_SELECTION:
                    numpkgs = len(installed_packages)
                    rangemsg = ""
                    if numpkgs > 1:
                        rangemsg = f". Must be 1-{numpkgs}"
                    print(f"{INVALID_SELECTION}{rangemsg}")
                else:
                    print(NONINT_SELECTION)
                continue
        packages = [installed_packages[selection - 1] for selection in selections]
        return packages

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

    def uninstall_kibana_saved_objects(self, packages: List[Package], username: str, password: str, force: bool):
        print(f"Preparing {len(packages)} for uninstall..")
        for package in packages:
            package.reload_installed_objects()
            package.uninstall(self.kibana_url, auth=(username, password))

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
        # default to orphan package in case of install from .ndjson
        manifest = PackageManifest(OrphanPackageData)
        package = Package(manifest)
        

        if filetype == 'application/x-tar' or encoding == 'gzip':
            # handle tarfile
            tar = tarfile.open(package_install_path)
            try:
                manifest = tar.extractfile('manifest.json')
                manifest = PackageManifest(manifest.read().decode('utf8'))
                package = Package(manifest)
                package.create_packages_index()
                # check if package exists already.
                existing = Package.find_by_slug(package.manifest.create_slug())
                if existing:
                    rmexisting = input(f"A Package titled {existing.manifest.name} is already installed, do you want to uninstall it? [y/n]") in "yY"
                    if rmexisting:
                        rmsuccess = existing.uninstall(self.kibana_url, auth=(username, password), force=True)
                        if rmsuccess:
                            print(f"Successfully removed existing package {existing.manifest.name}.")
                
            except KeyError:
                print("Package must contain a manifest.json")
                exit(0)
            for member in manifest.file_list:
                # should we validate the json before sending it up to kibana?
                kibana_objects_file = BytesIO(tar.extractfile(member).read())
                result = self.import_kibana_saved_objects(username=username, password=password,
                                                 kibana_objects_file=kibana_objects_file)
                kibana_objects_file.close()
                installation_statuses.append(self._process_package_installation_results(package, result))
        # Should we remove this and ONLY install validatable packages?
        elif filetype in ('application/json', 'text/plain') or any(
                [package_install_path.endswith('ndjson'), package_install_path.endswith('json')]):
            with open(package_install_path, 'r') as kibana_objects_file:
                result = self.import_kibana_saved_objects(username=username, password=password,
                                                 kibana_objects_file=kibana_objects_file)
                installation_statuses.append(self._process_package_installation_results(package, result))
        else:
            self.logger.error("Files must be one of: .ndjson, .json, .tar.xz, .tar.gz")
            # TODO raise exception
        
        if not all(installation_statuses):
            print(f"\r\n{package.manifest.name} installation failed.")
            if not self.verbose:
                print("Use --verbose flag to see more error detail.\n")
        else:
            package.register()
            print(f"\r\n{package.manifest.name} installation succeeded!")

    def list(self, username: Optional[str] = None, password: Optional[str] = None):
        """
        List packages currently installed for this instance

        :param username: The name of the Kibana user to authenticate with
        :param password: The corresponding Kibana password
        """
        packages = Package.search_installed_packages()
        if not packages:
            print("Could not find any installed packages")
            return None
        print("\r\nInstalled Packages:\n")
        for package in packages:
            total = 0
            numobjs = len(package.installed_objects)
            print(f"Package Name:\n * {package.manifest.name}")
            print(f"Description:\n * {package.manifest.description}")
            objects_by_type = defaultdict(list)
            print(f"Objects contained:")
            for obj in package.installed_objects:
                objects_by_type[obj.object_type].append(obj)
            for object_type, objs in objects_by_type.items():
                numobjs = len(objs)
                total += numobjs
                print(f" - {object_type}: {numobjs}")
            print(f" Total Objects: {total}")

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

    def uninstall(self, username: Optional[str] = None,
                        password: Optional[str] = None,
                        package_name: Optional[str] = None,
                        remove_from_all_spaces: Optional[bool] = False):
        to_uninstall = self._select_packages_for_uninstall(package_name)
        if not username or not password:
            auth = self._get_kibana_auth_securely(username, password)
        force = bool(remove_from_all_spaces)
        self.uninstall_kibana_saved_objects(to_uninstall, *auth, force=force)
        

        

        
