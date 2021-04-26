from __future__ import annotations

import logging
import mimetypes
import tarfile
import json
import re
import os
import requests
import urllib3


from getpass import getpass
from tabulate import tabulate
from uuid import uuid4
from unidecode import unidecode
from io import BytesIO, IOBase
from typing import AnyStr, Optional, Tuple, IO, List, Union
from urllib.parse import urlparse


from dynamite_nsm.logger import get_logger
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.utilities import PrintDecorations, get_environment_file_dict
from dynamite_nsm.services.kibana.config import ConfigManager as KibanaConfigManager
from dynamite_nsm.services.kibana.package.mappings import PACKAGES_INDEX_MAPPING, \
                                                          PACKAGES_INDEX_NAME
from dynamite_nsm.services.kibana.package.schemas import ORPHAN_OBJECT_PACKAGE_MANIFEST_DATA \
                                                        as OrphanPackageData, \
                                                        InstalledObjectSchema, \
                                                        PackageManifestSchema, \
                                                        SchemaToObject


def _get_kibana_url() -> str:
    """tries to pull from local kibana configs for kibana url, falling back to primary ip addr.

    Returns:
        str: the inferred kibana url
    """
    env_dict = get_environment_file_dict()
    kibana_conf_dir = env_dict.get('KIBANA_PATH_CONF')
    if not kibana_conf_dir:
        return f'http://{get_primary_ip_address()}:5601'
    else:
        confman = KibanaConfigManager(kibana_conf_dir)
        return f'http://{confman.host}:{confman.port}'


class PackageLoadError(Exception):
    pass


class PackageUninstallationError(Exception):
    pass


class InstalledObject(SchemaToObject):

    def __init__(self, json_data) -> None:
        super().__init__(json_data, InstalledObjectSchema())

    @classmethod
    def from_kwargs(cls, title, object_type, object_id, space_id) -> InstalledObject:
        """Create instance of InstalledObject from kwargs
           instead of a dict or json string.

        Returns:
            InstalledObject: an InstalledObject instance
            with the properties supplied in kwargs.
        """
        data = {}
        data['title'] = title
        data['object_type'] = object_type
        data['object_id'] = object_id
        data['space_id'] = space_id
        obj = cls(data)
        return obj

    @classmethod
    def from_installation_result(cls, responsedata, **kwargs) -> InstalledObject:
        """Automatically parses the output from installing
           a Saved Object in Kibana and returns an instance of InstalledObject

        Args:
            responsedata (dict): The dictionary representation of the
            JSON returned from Kibana's API when installing a saved object

        Returns:
            InstalledObject: an InstalledObject instance
            representing the recently installed saved object.
        """
        data = {}
        data['title'] = responsedata.get(
            'meta', {'title': 'untitled object'}).get('title')
        data['object_type'] = responsedata.get('type', None)
        # this is the id of the saved object, not the document for tracking
        data['object_id'] = responsedata.get('id', None)
        data.update(kwargs)
        obj = cls.from_kwargs(**data)
        return obj

    def __repr__(self) -> str:
        return f"<InstalledObect id: {self.object_id}, title: {self.title} >"


class PackageManifest(SchemaToObject):
    def __init__(self, json_data):
        """Object representing the PackageManifest (manifest.json) within a dynamite package

        Args:
            json_data (dict or str): the JSON Data matching the PckageManifest schema to be validated in string
            or dictionary format.
        """
        super().__init__(json_data, PackageManifestSchema())
        self.data['slug'] = self.create_slug()

    def create_slug(self) -> str:
        """creates a slug based on the name provided in the manifest

        Returns:
            str: the slug
        """
        name = self.name or OrphanPackageData.get('name')
        # using unidecode to support unicode/ascii in the package manifest data.
        slug = unidecode(name).lower()
        return re.sub(r'[\W_]+', '-', slug)

    def json(self) -> str:
        """JSON Representation of the package manifest with package slug

        Returns:
            str: [description]
        """
        if not self.data.get('slug', None):
            self.data['slug'] = self.slug
        return json.dumps(self.data)

    def __repr__(self) -> str:
        return f"<PackageManifest(name={self.name}, author={self.author})>"


class Package():

    package_index_name = PACKAGES_INDEX_NAME
    # assume we're operating locally by default if nothing supplied for kibana target
    
    es_proxy_url = f"{_get_kibana_url()}/api/console/proxy"
    auth = ('admin', 'admin')
    _installed_objects = []

    def __init__(self, manifest: PackageManifest,
                 installed_objects: Optional[list] = None,
                 auth: Optional[tuple] = ('admin', 'admin'),
                 id: Optional[str] = None,
                 kibana_target: Optional[str] = None) -> None:
        """Initializes a Package object with a provided manifest, optional

        Args:
            manifest (PackageManifest): the validated manifeset object for the package.
            installed_objects (List(InstalledObject)), optional): any pre-collected installed objects for the package.
                Defaults to None.

            auth (Optional[str], optional): username and password tuple for authentication.
                Defaults to ('admin', 'admin')).

            id (Optional[str], optional): the Id that will be used for the ES document and uninstallation.
                Defaults to None.
        """

        self.manifest = manifest
        if installed_objects:
            self._installed_objects = installed_objects
        self.id = id
        self.auth = auth or Package.auth
        self.slug = self.manifest.create_slug()
        if not kibana_target:
            kibana_target = _get_kibana_url()
        self.es_proxy_url = self.build_proxy_url_from_target(kibana_target)

    @staticmethod
    def build_proxy_url_from_target(kibana_target: str) -> str:
        url = urlparse(kibana_target)
        return f"{url.scheme}://{url.netloc}/api/console/proxy"

    @staticmethod
    def es_search(query: dict, kibana_target: Optional[str] = None) -> dict:
        """Performs an elasticsearch query against the dynamite packages index.

        Args:
            query (dict): ES DSL for the query

        Raises:
            ValueError: If response from ES is nonsuccess (not 200 series status)

        Returns:
            result: dict
        """
        proxyurl = Package.build_proxy_url_from_target(kibana_target) if kibana_target else Package.es_proxy_url
        result = requests.post(f"{proxyurl}?method=GET&path={Package.package_index_name}/_search",
                               json=query,
                               verify=False,
                               auth=Package.auth,
                               headers={'kbn-xsrf': 'true'})
        if result.status_code not in range(200, 299):
            raise PackageLoadError("Failed to fetch package data. You may not have any packages installed. "
                                   "Does the dynamite-packages index exist?")
        num_returned = result.json().get('hits', {
            "total": {
                "value": 0,
            },
            "hits": []
        }).get('total').get('value')

        if not num_returned:
            return {}
        return result.json()

    def reload_installed_objects(self) -> list:
        """Fetches Package information from ES

        Performs a query based on the existing package manifest
        and loads all installed objects
        into self._installed_objects

        Returns:
            list[InstalledObjects]: List of installed Objects
        """
        # should we instead perform inner hits query on nested object to get objects for current slug?
        query = {
            "query": {
                "match": {
                    "manifest.slug": {
                        "query": self.slug,
                        "minimum_should_match": 1
                    }
                }
            }
        }

        result = self.es_search(query, kibana_target=self.es_proxy_url)
        if not result:
            return []
        packagesdata = [r['_source'] for r in result['hits']['hits']]
        pkg = packagesdata[0]
        instobjs = [InstalledObject.from_kwargs(
            **iobj) for iobj in pkg.get('installed_objects')]
        self._installed_objects = instobjs
        return self._installed_objects

    @property
    def installed_objects(self) -> list:
        if not self._installed_objects:
            self.reload_installed_objects()
        return self._installed_objects

    def _check_index_exists(self) -> bool:
        """Checks if the dynamite packages index exists in ES

        Returns:
            bool: success
        """
        res = requests.post(
            f"{self.es_proxy_url}?method=HEAD&path={self.package_index_name}",
            verify=False,
            auth=self.auth,
            headers={'kbn-xsrf': 'true'})
        return res.status_code == 200

    @staticmethod
    def load_from_archive(package_path, kibana_target: Optional[str] = None) -> Package:
        """Loads a package from disk

        Args:
            package_path (str): path to the archive on disk

        Returns:
            Package: a Package instance from the loaded package file.
        """
        tar = tarfile.open(package_path)
        try:
            manifest = tar.extractfile('manifest.json')
            manifest = PackageManifest(manifest.read().decode('utf8'))
            package = Package(manifest, kibana_target=kibana_target)
            return package
        except KeyError:
            raise PackageLoadError("Package must contain a manifest.json")

    def create_packages_index(self) -> bool:
        """Create the dynamite packages index if it does not already exist

        Returns:
            bool: success
        """
        exists = self._check_index_exists()
        if not exists:
            res = requests.post(
                url=f"{self.es_proxy_url}?method=PUT&path={self.package_index_name}",
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
        """prepares the ElasticSearch input for persisting package data/metadata

        Raises:
            ValueError: Something went wrong (eg. ES is down)

        Returns:
            dict: the ES input for the provided package, with any kwarg overrides provided.
        """
        if self.id is None and 'id' not in kwargs:
            raise ValueError(
                "An ID must be supplied before saving to ElasticSearch")
        inputdict = self.__dict__
        overrides = inputdict.keys()
        for arg, val in kwargs.items():
            if arg in overrides:
                inputdict[arg] = val
        return inputdict

    def result_to_object(self, result: dict, space_id: Optional[str] = None) -> InstalledObject:
        """Takes an installation result output from kiban API and returns an InstalledObject

        Args:
            result (dict): result from installation call to kibana
            space_id (Optional[str], optional): set space ID for the installed object instance. Defaults to None.

        Returns:
            InstalledObject: Instance representing the object that was installed.
        """
        obj = InstalledObject.from_installation_result(
            result, space_id=space_id)
        if space_id:
            obj.space_id = space_id
        return obj

    def uninstall(self, kibana_url: str, auth: Tuple[str], force: Optional[bool] = False) -> bool:
        """uninstalls a package from kibana

        Args:
            kibana_url (str): url for kibana
            auth (Tuple[str]): Authentication for kibana
            force (Optional[bool], optional): If True, objects with matching ID is uninstalled from all spaces.
                Defaults to True.

        Returns:
            bool: success
        """
        statuses = []
        for iobj in self.installed_objects:

            if iobj.space_id:
                if not force:
                    force = input(
                        f"{iobj.title} was installed to a space. Do you want to remove it from all spaces? [y/n]") in \
                            "yY"
                url = f'{kibana_url}/s/{iobj.space_id}/api/saved_objects'
            else:
                force = True
                url = f'{kibana_url}/api/saved_objects'
            delurl = f"{url}/{iobj.object_type}/{iobj.object_id}"
            if force:
                delurl += "?force=true"
            resp = requests.delete(delurl, auth=auth, verify=False, headers={
                                   'kbn-xsrf': 'true'})
            success = resp.status_code in range(200, 299)
            if success:
                self.deregister()
            else:
                raise PackageUninstallationError(f"Something went wrong trying to uninstall a package: "
                                                 f"{resp.json().get('message')}")
            statuses.append(success)
        return all(statuses)

    def deregister(self) -> bool:
        """Deregisters a package from the dynamite-packages index

        Returns:
            bool: success
        """
        exists = self._check_index_exists()
        if not exists:
            # Should this throw an error?
            return False
        res = requests.post(f"{self.es_proxy_url}?method=DELETE&path={self.package_index_name}/_doc/{self.id}",
                            verify=False,
                            auth=self.auth,
                            headers={'kbn-xsrf': 'true'})
        return res.status_code in range(200, 299)

    def register(self) -> bool:
        """Registers a package in the dynamite-packages index

        Returns:
            bool: success
        """
        self.create_packages_index()
        id = uuid4()
        res = requests.post(f"{self.es_proxy_url}?method=POST&path={self.package_index_name}/_doc/{id}",
                            json=self.es_input(id=str(id)),
                            verify=False,
                            auth=self.auth,
                            headers={'kbn-xsrf': 'true'})
        return res.status_code in range(200, 299)

    @staticmethod
    def find_by_id(package_id: str, kibana_target: Optional[str] = None) -> Union['Package', None]:
        """fetches an installed package by their id

        Args:
            package_id (str): uuid for package (source id, not document id.)

        Raises:
            ValueError: Something went wrong performing search. e.g: ES is down
        Returns:
            Union[Package, None]: A Package instance fetched by id or None if no package found

        """

        query = {
            "query": {
                "match": {
                    "id": {
                        "query": package_id,
                        "minimum_should_match": 1
                    }
                }
            }
        }

        result = Package.es_search(query, kibana_target=kibana_target)
        if not result:
            return None
        packagesdata = [r['_source'] for r in result['hits']['hits']]
        pkg = packagesdata[0]
        manifest = PackageManifest(pkg.get('manifest'))
        instobjs = [InstalledObject.from_kwargs(
            **iobj) for iobj in pkg.get('installed_objects')]
        package = Package(manifest, instobjs, id=pkg.get('id'), kibana_target=kibana_target)
        return package

    @staticmethod
    def find_by_slug(package_slug: str, kibana_target: Optional[str] = None) -> Package:
        """Find a package by its slug

        Args:
            package_slug (str): slug for package

        Raises:
            ValueError: Something went wrong performing search. e.g: ES is down

        """
        query = {
            "query": {
                "match": {
                    "manifest.slug": {
                        "query": package_slug,
                        "minimum_should_match": 1
                    }
                }
            }
        }

        result = Package.es_search(query, kibana_target)
        if not result:
            return None
        packagesdata = [r['_source'] for r in result['hits']['hits']]
        pkg = packagesdata[0]
        manifest = PackageManifest(pkg.get('manifest'))
        instobjs = [InstalledObject.from_kwargs(
            **iobj) for iobj in pkg.get('installed_objects')]
        package = Package(manifest, instobjs, id=pkg.get('id'), kibana_target=kibana_target)
        return package

    @staticmethod
    def search_installed_packages(package_name=None, kibana_target: Optional[str] = None) -> list:
        """
        Returns Packages with wildcard search on provided package name string,
            returns all packages if package name not supplied

        Args:
            package_name ([str], optional): UUID of the package. Defaults to None.


        Returns:
            list: List of Packages
        """
        query = {
            "aggs": {
                "manifest.name": {
                    "terms": {
                        "field": "manifest.name.keyword"
                    }
                }
            }
        }

        if package_name:
            query["query"] = {
                "wildcard": {
                    "package_name": {
                        "wildcard": f"*{package_name}*",
                    }
                }
            }

        result = Package.es_search(query, kibana_target)
        if not result:
            return None

        # If we want to just display the titles and num packages, we can pull from aggs result instead.
        packagesdata = [r['_source'] for r in result['hits']['hits']]
        packages = []
        for pkg in packagesdata:
            manifest = PackageManifest(pkg.get('manifest'))
            instobjs = [InstalledObject.from_kwargs(
                **iobj) for iobj in pkg.get('installed_objects')]
            package = Package(manifest, instobjs, id=pkg.get('id'), kibana_target=kibana_target)
            packages.append(package)
        return packages


class SavedObjectsManager():
    def __init__(self,
                 stdout: Optional[bool] = True,
                 verbose: Optional[bool] = False,
                 target: Optional[str] = None) -> None:
        """Initializes the SavedObjectsManager

        Args:
            stdout: Print the output to console
            verbose: Include detailed debug messages
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger(
            str('KIBANA.PACKAGE_MANAGER'), level=log_level, stdout=stdout)
        self.verbose = verbose
        self._installed_packages = None
        self._kibana_url = target
        self._validate_kibana_target(target)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @property
    def kibana_url(self) -> str:
        if not self._kibana_url:
            self._kibana_url = _get_kibana_url()
        return self._kibana_url

    def _validate_kibana_target(self, target: Optional[str] = None) -> bool:
        try:
            targ = target or self.kibana_url
            result = urlparse(targ)
            return all([result.scheme, result.netloc])
        except Exception as e:
            self.logger.error(f"Could not validate kibana target url {self.kibana_url}")
            if self.verbose:
                self.logger.exception(e)
            exit(0)

    def check_kibana_connection(self, username, password) -> bool:
        auth = (username, password)
        try:
            if self.verbose:
                self.logger.info('Checking if kibana API is up..')
            resp = requests.get(f'http://{self.kibana_url}:5601/api/status', auth=auth)
            if resp.status_code == 200:
                statusstate = resp.json().get('status', {'overall': {'state': 'unknown'}}).get('overall').get('state')
                if self.verbose:
                    self.logger.info(f"Kibana status: {statusstate}")
        except requests.exceptions.ConnectionError as e:
            self.logger.exception(e)
            raise e

    @staticmethod
    def _get_kibana_auth_securely(username: Optional[str] = None, password: Optional[str] = None) -> Tuple[str, str]:
        """Gets kibana auth info from user input

        Args:
            username (Optional[str], optional): the username. Defaults to None.
            password (Optional[str], optional): the password. Defaults to None.

        Returns:
            Tuple[str, str]: auth tuple
        """
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
                self.logger.error(
                    f"{error['title']} - {error.get('error', {'type': 'unknown'})['type']}")
                if self.verbose:
                    self.logger.error(f"Full Error:\n{error}\n")
        for installed in kibana_response.get('successResults', []):
            if self.verbose:
                self.logger.info(installed)
            installed_obj = package.result_to_object(installed)
            package.installed_objects.append(installed_obj)
        return success

    def _select_packages_for_uninstall(self, package_name) -> List[Package]:
        INVALID_SELECTION = "Not a valid selection"
        NONINT_SELECTION = "Selections must be integers"
        print("\n\nSelect a package to uninstall:")
        installed_packages = Package.search_installed_packages(package_name, kibana_target=self.kibana_url)
        if not installed_packages:
            self.logger.error("Could not find any packages to uninstall.")
            exit(0)
        for package in installed_packages:
            idx = installed_packages.index(package)
            if package.manifest.description and len(package.manifest.description) > 50:
                desc = f"{package.manifest.description[:50]}.."
            else:
                desc = package.manifest.description
            lbb = PrintDecorations.colorize('[', 'bold')
            rbb = PrintDecorations.colorize(']', 'bold')
            packagename = PrintDecorations.colorize(package.manifest.name, 'bold')
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
                    self.logger.error(f"{INVALID_SELECTION}{rangemsg}")
                else:
                    self.logger.error(NONINT_SELECTION)
                continue
        packages = [installed_packages[selection - 1] for selection in selections]
        return packages

    def browse_saved_objects(self, username: Optional[str] = None, password: Optional[str] = None,
                             saved_object_type: Optional[str] = None) -> requests.Response:
        """browse saved objects in kibana whether or not they are part of a dynamite package.

        Args:
            username (Optional[str], optional): kibana auth username, Defaults to None.
            password (Optional[str], optional): kibana auth passwd. Defaults to None.
            saved_object_type (Optional[str], optional): type of objects to limit the search to. Defaults to None.

        Returns:
            requests.Response: data returned from kibana
        """
        auth = self._get_kibana_auth_securely(username, password)
        self.check_kibana_connection(*auth)
        if saved_object_type:
            resp = requests.get(
                f'{self.kibana_url}/api/saved_objects/_find?type={saved_object_type}', auth=auth)
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
            self.logger.error(
                f'Kibana endpoint returned a {resp.status_code} - {resp.text}')
            # TODO raise exception
        return resp

    def uninstall_kibana_saved_objects(self,
                                       packages: List[Package], username: str, password: str, force: bool) -> None:
        """uninstall packages and their saved objects from kibana

        Args:
            packages (List[Package]): A list of packages to uninstall
            username (str): ES Auth username
            password (str): ES Auth password
            force (bool): force uninstall from all spaces?
        """
        self.logger.info(f"Preparing {len(packages)} for uninstall..")
        for package in packages:
            package.reload_installed_objects()
            try:
                uninstalled = package.uninstall(self.kibana_url, auth=(username, password))
                if uninstalled:
                    self.logger.info(f"Uninstalled {package.manifest.name} successfully..")
            except PackageUninstallationError as e:
                self.logger.exception(e)
                self.logger.error(f"Could not uninstall package {package.id} ({package.manifest.name})")

    def import_kibana_saved_objects(self, kibana_objects_file: IO[AnyStr],
                                    username: str = 'admin',
                                    password: str = 'admin',
                                    space: Optional[str] = None,
                                    overwrite: Optional[bool] = True,
                                    create_copies: Optional[bool] = False) -> dict:
        """Import saved objects into kibana from a package file

        Args:
            username (str): kibana auth usrname. Defaults to 'admin'
            password (str): kibana auth passwd.  Defaults to 'admin'
            kibana_objects_file (IO[AnyStr]): the file to parse and install
            space (Optional[str], optional): id of the space to install the object to. Defaults to None.
            overwrite (Optional[bool], optional): overwrite existing ids?. Defaults to True.
            create_copies (Optional[bool], optional): create copies if an object exists with the same id?.
                Defaults to False.

        Raises:
            ValueError: Something went wrong

        Returns:
            dict: Response from kibana
        """
        auth = self._get_kibana_auth_securely(username, password)
        self.check_kibana_connection(*auth)

        if space:
            url = f'{self.kibana_url}/s/{space}/api/saved_objects/_import'
        else:
            url = f'{self.kibana_url}/api/saved_objects/_import'
        if all([overwrite, create_copies]):
            raise ValueError(
                "createNewCopies and overwrite cannot be used together.")

        params = {'overwrite': overwrite, 'createNewCopies': create_copies}

        # TODO: Catch connection denied when kibana is down and handle/inform user gracefully
        if isinstance(kibana_objects_file, IOBase):
            reqdata = {'file': ('dynamite_import.ndjson', kibana_objects_file)}
        else:
            reqdata = {'file': kibana_objects_file}
        resp = requests.post(url, params=params, auth=auth,
                             files=reqdata, headers={'kbn-xsrf': 'true'})
        if resp.status_code not in range(200, 299):
            self.logger.error(
                f'Kibana endpoint returned a {resp.status_code} - {resp.text}')
            # TODO raise exception
        return resp.json()

    def install(self, package_install_path: str, username: Optional[str] = 'admin',
                password: Optional[str] = 'admin', ignore_warnings: Optional[bool] = False) -> None:
        """Install a package. A package can be given as an archive or directory.
            A package must contain one or more ndjson files and a manifest.json

        Args:
            package_install_path (str): path to the file or folder of files
            username (Optional[str], optional): kibana auth usrname. Defaults to None.
            password (Optional[str], optional): kibana auth password. Defaults to None.
        """
        self.check_kibana_connection(username, password)
        is_folder = os.path.isdir(package_install_path)
        filepaths = []
        if not is_folder:
            filepaths = [package_install_path]
        else:
            # check for installable items by extension, they will be verified by mimetype later.
            acceptable_extensions = ['tar.xz', 'tar.gz']
            for itm in os.listdir(package_install_path):
                for ex in acceptable_extensions:
                    if itm.endswith(ex):
                        filepaths.append(f"{package_install_path}{itm}")
                        break
            self.logger.info(f"Found {len(filepaths)} packages to install.")
        for _filepath in filepaths:
            filepath = os.path.abspath(_filepath)
            # check mimetype of the file to determine how to proceed
            filetype, encoding = mimetypes.MimeTypes().guess_type(filepath)
            installation_statuses = []
            # default to orphan package in case of install from .ndjson
            manifest = PackageManifest(OrphanPackageData)
            package = Package(manifest, kibana_target=self.kibana_url)
            if filetype == 'application/x-tar' or encoding == 'gzip':
                # handle tarfile
                tar = tarfile.open(filepath)
                try:
                    manifest = tar.extractfile('manifest.json')
                    manifest = PackageManifest(manifest.read().decode('utf8'))
                    package = Package(manifest, kibana_target=self.kibana_url)
                    package.create_packages_index()
                    # check if package exists already.
                    existing = Package.find_by_slug(
                        package.manifest.create_slug(), kibana_target=self.kibana_url)
                    if existing and not ignore_warnings:
                        rmexisting = input(
                            f"A Package titled {existing.manifest.name} is already installed, "
                            "do you want to uninstall it? [y/n]") in "yY"
                        if rmexisting:
                            if not username or not password:
                                username, password = self._get_kibana_auth_securely(username, password)
                            rmsuccess = existing.uninstall(
                                self.kibana_url, auth=(username, password), force=True)
                            if rmsuccess:
                                self.logger.info(
                                    f"Successfully removed existing package {existing.manifest.name}.")

                except (KeyError, PackageLoadError) as e:
                    self.logger.exception(e)
                    exit(0)
                for member in manifest.file_list:
                    # should we validate the json before sending it up to kibana?
                    kibana_objects_file = BytesIO(
                        tar.extractfile(member).read())
                    result = self.import_kibana_saved_objects(username=username, password=password,
                                                              kibana_objects_file=kibana_objects_file)
                    kibana_objects_file.close()
                    installation_statuses.append(
                        self._process_package_installation_results(package, result))
            # Should we remove this and ONLY install validatable packages?
            elif filetype in ('application/json', 'text/plain') and filepath.endswith('ndjson'):
                with open(filepath, 'r') as kibana_objects_file:
                    result = self.import_kibana_saved_objects(username=username, password=password,
                                                              kibana_objects_file=kibana_objects_file)
                    installation_statuses.append(
                        self._process_package_installation_results(package, result))
            else:
                self.logger.error(
                    "Files must be one of: .ndjson, .json, .tar.xz, .tar.gz")
                # TODO raise exception

            if not all(installation_statuses):
                self.logger.error(f"\r\n{package.manifest.name} installation failed.")
                if not self.verbose:
                    self.logger.info("Use --verbose flag to see more error detail.\n")
            else:
                package.register()
                self.logger.info(f"{package.manifest.name} installation succeeded!")

    def list(self, username: Optional[str] = None,
             password: Optional[str] = None, pretty: Optional[bool] = False) -> Union[str, dict]:
        """List packages currently installed for this instance

        Args:
            username (Optional[str], optional): kibana auth username. Defaults to None.
            password (Optional[str], optional): kibana auth passwd. Defaults to None.
        """
        try:
            packages = Package.search_installed_packages(kibana_target=self.kibana_url)
        except PackageLoadError as e:
            self.logger.exception(e)
            exit(0)
        if not packages:
            self.logger.error("Could not find any installed packages")
            return None

        if pretty:
            self.logger.info("\r\nInstalled Packages:\n")
            headers = ["Package Name", "Package ID", "Description",
                       "Author", "Objects Within", "Total Objects"]
            table = []
            for package in packages:
                row = []
                total = 0
                row.append(package.manifest.name)
                row.append(package.id)
                row.append(package.manifest.description)
                row.append(package.manifest.author)
                objlines = []
                for obj in package.installed_objects:
                    objlines.append(f"[{obj.object_type}] - {obj.title}")
                    total += 1
                row.append("\n".join(sorted(objlines)))
                row.append(total)
                table.append(row)
            return tabulate(table, headers=headers, tablefmt="fancy_grid")
        else:
            data = []
            for package in packages:
                data.append(package.es_input())
            return data

    def list_saved_objects(self, username: Optional[str] = None, password: Optional[str] = None,
                           saved_object_type: Optional[str] = None, pretty: Optional[bool] = False) -> Union[str, dict]:
        """List the saved_objects currently installed irrespective of which "package" the belong too

        Args:
            username (Optional[str], optional): The name of the Kibana user to authenticate with. Defaults to None.
            password (Optional[str], optional): The corresponding Kibana password. Defaults to None.
            saved_object_type (Optional[str], optional): One of the following supported saved_object types:
                            ['config', 'dashboard', 'index-pattern', 'search', 'timelion-sheet', 'visualization'].
                            Defaults to None.
        """

        username, password = self._get_kibana_auth_securely(
            username, password)
        fetched_data = self.browse_saved_objects(
            username, password, saved_object_type=saved_object_type).json()
        table = []
        headers = ["Title", "Object Type",  "Object ID"]
        for obj in fetched_data.get('saved_objects', []):
            kibana_object_id = obj['id']
            kibana_object_type = obj['type']
            kibana_object_title = obj['attributes'].get('title', '')
            if pretty:
                table.append(
                    [kibana_object_title, kibana_object_type, kibana_object_id])
            else:
                table.append({
                    "title": kibana_object_title,
                    "type": kibana_object_type,
                    "id": kibana_object_id
                })
        if pretty:
            return tabulate(table, headers=headers, tablefmt="fancy_grid")
        else:
            return table

    def uninstall(self, username: Optional[str] = None,
                  password: Optional[str] = None,
                  package_name: Optional[str] = None,
                  package_id: Optional[str] = None,
                  remove_from_all_spaces: Optional[bool] = False) -> None:
        """Uninstall packages from instance

        Args:
            username (Optional[str], optional): kibana auth usrname. Defaults to None.
            password (Optional[str], optional): kibana auth passwd. Defaults to None.
            package_name (Optional[str], optional): name of the package to search for. Defaults to None.
            remove_from_all_spaces (Optional[bool], optional): force removal from all spaces. Defaults to False.
        """
        if package_id and package_name:
            self.logger.error(
                "Package Name and Package Id cannot be used together")
            exit(0)
        try:
            if not package_id:
                to_uninstall = self._select_packages_for_uninstall(package_name)    
            else:
                to_uninstall = Package.find_by_id(package_id, kibana_target=self.kibana_url)
                if not to_uninstall:
                    self.logger.error(
                        f"Could not find package with id {package_id}")
                    exit(0)
                to_uninstall = [to_uninstall]
            
        except PackageLoadError as e:
            self.logger.exception(e)
            exit(0)
        if not username or not password:
            auth = self._get_kibana_auth_securely(username, password)
        force = bool(remove_from_all_spaces)
        self.check_kibana_connection(username, password)
        self.uninstall_kibana_saved_objects(to_uninstall, *auth, force=force)
