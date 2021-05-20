from __future__ import annotations
import re
import json
import logging
import tarfile
from uuid import uuid4
from datetime import datetime
from unidecode import unidecode
from urllib.parse import urlparse
from typing import Dict, Optional, Tuple, List

import requests
import progressbar

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.kibana.package import mappings, schemas
from dynamite_nsm.services.kibana.config import ConfigManager as KibanaConfigManager


PROGRESS_BAR_UNINSTALL_WIDGETS = [
        '\033[92m',
        '{} '.format(datetime.strftime(datetime.utcnow(), '%Y-%m-%d %H:%M:%S')),
        '\033[0m',
        '\033[0;36m',
        'UNINSTALL_TRACKER ',
        '\033[0m',
        '         | ',
        progressbar.Percentage(),
        ' ', progressbar.Bar(),
        ' ', progressbar.FormatLabel(''),
        ' ', progressbar.ETA()
    ]


def get_kibana_url() -> str:
    """tries to pull from local kibana configs for kibana url, falling back to primary ip addr.

    Returns:
        str: the inferred kibana url
    """
    env_dict = utilities.get_environment_file_dict()
    kibana_conf_dir = env_dict.get('KIBANA_PATH_CONF')
    if not kibana_conf_dir:
        return f'http://{utilities.get_primary_ip_address()}:5601'
    else:
        confman = KibanaConfigManager(kibana_conf_dir)
        return f'http://{confman.host}:{confman.port}'


class PackageLoadError(Exception):
    pass


class PackageUninstallationError(Exception):
    pass


class InstalledObject(schemas.SchemaToObject):

    def __init__(self, json_data) -> None:
        self.title = None
        self.object_type = None
        self.object_id = None
        self.tenant = None

        super().__init__(json_data, schemas.InstalledObjectSchema())

    @classmethod
    def from_kwargs(cls, title, object_type, object_id, tenant) -> InstalledObject:
        """Create instance of InstalledObject from kwargs
           instead of a dict or json string.

        Returns:
            InstalledObject: an InstalledObject instance
            with the properties supplied in kwargs.
        """
        data = {'title': title, 'object_type': object_type, 'object_id': object_id, 'tenant': tenant}
        obj = cls(data)
        return obj

    @classmethod
    def from_installation_result(cls, response_data, **kwargs) -> InstalledObject:
        """Automatically parses the output from installing
           a Saved Object in Kibana and returns an instance of InstalledObject

        Args:
            response_data (dict): The dictionary representation of the
            JSON returned from Kibana's API when installing a saved object

        Returns:
            InstalledObject: an InstalledObject instance
            representing the recently installed saved object.
        """
        data = {'title': response_data.get('meta', {}).get('title', 'Untitled'),
                'object_type': response_data.get('type', None),
                'object_id': response_data.get('id', None)}
        data.update(kwargs)
        # print(data)
        obj = cls.from_kwargs(**data)
        return obj

    def __repr__(self) -> str:
        reprstr = f"<InstalledObject id: {self.object_id}, title: {self.title} "
        if self.tenant:
            reprstr += f"tenant: {self.tenant} "
        reprstr += ">"

        return reprstr


class PackageManifest(schemas.SchemaToObject):
    def __init__(self, json_data):
        """Object representing the PackageManifest (manifest.json) within a dynamite package

        Args:
            json_data (dict or str): the JSON Data matching the PackageManifest schema to be validated in string
            or dictionary format.
        """
        self.file_list = []
        self.author = None
        self.slug = None
        self.name = None
        super().__init__(json_data, schemas.PackageManifestSchema())
        self.data['slug'] = self.create_slug()

    def create_slug(self) -> str:
        """Creates a slug based on the name provided in the manifest

        Returns:
            The slug
        """
        name = self.name or schemas.ORPHAN_OBJECT_PACKAGE_MANIFEST_DATA.get('name')
        # using unidecode to support unicode/ascii in the package manifest data.
        slug = unidecode(name).lower()
        return re.sub(r'[\W_]+', '-', slug)

    def json(self) -> str:
        """JSON Representation of the package manifest with package slug

        Returns:
            str: A JSON representation of the package manifest.
        """
        if not self.data.get('slug', None):
            self.data['slug'] = self.slug
        return json.dumps(self.data)

    def __repr__(self) -> str:
        return f"<PackageManifest(name={self.name}, author={self.author})>"


class Package:
    package_index_name = mappings.PACKAGES_INDEX_NAME
    # assume we're operating locally by default if nothing supplied for kibana target
    es_proxy_url = f"{get_kibana_url()}/api/console/proxy"
    _installed_objects = []

    def __init__(self, manifest: PackageManifest,
                 installed_objects: Optional[list] = None,
                 auth: Optional[tuple] = ('admin', 'admin'), package_id: Optional[str] = None,
                 kibana_target: Optional[str] = None, stdout: Optional[bool] = True,
                 verbose: Optional[bool] = False,
                 autoload_installed_objects: Optional[bool] = True) -> None:
        """Initializes a Package object with a provided manifest, optional

        Args:
            manifest (PackageManifest): The validated manifest object for the package.
            installed_objects: Any pre-collected installed packages for the package. Defaults to None.
            auth: The username and password tuple for authentication. Defaults to ('admin', 'admin')).
            package_id: The Id that will be used for the ES document and uninstallation.
                Defaults to None.
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger(
            str('kibana.package'), level=log_level, stdout=stdout)
        self.manifest = manifest
        if installed_objects:
            self._installed_objects = installed_objects
        self.id = package_id
        self.auth = auth
        self.slug = self.manifest.create_slug()
        if not kibana_target:
            kibana_target = get_kibana_url()
        self.es_proxy_url = self.build_proxy_url_from_target(kibana_target)
        self.autoload_installed_objects = autoload_installed_objects

    @staticmethod
    def _parse_package_metadata(es_query_result: Dict):
        packages_data = [r['_source'] for r in es_query_result['hits']['hits']]
        try:
            pkg = packages_data[0]
        except IndexError:
            return None
        return pkg

    @staticmethod
    def build_proxy_url_from_target(kibana_target: str) -> str:
        url = urlparse(kibana_target)
        return f'{url.scheme}://{url.netloc}/api/console/proxy'

    @staticmethod
    def package_index_search(query: dict, kibana_target: Optional[str] = None,
                             auth: Tuple[str, str] = ('admin', 'admin')) -> Dict:
        """Performs an Elasticsearch query against the dynamite packages index.
        Args:
            kibana_target: The URL to the Kibana instance your wish to connect to (E.G https://my_kibana.local:5601)
            query: ES DSL for the query
            auth: The username and password tuple for authentication. Defaults to ('admin', 'admin')).
        Raises:
            ValueError: If response from ES is invalid (not 200 series status)

        Returns:
            result: The result of the elasticsearch query.
        """
        proxy_url = Package.build_proxy_url_from_target(kibana_target) if kibana_target else Package.es_proxy_url
        try:
            result = requests.post(f"{proxy_url}?method=GET&path={Package.package_index_name}/_search",
                                   json=query,
                                   verify=False,
                                   auth=auth,
                                   headers={'kbn-xsrf': 'true'})
            if result.status_code not in range(200, 299):
                raise PackageLoadError("Failed to fetch package data. You may not have any packages installed. "
                                       "Does the dynamite-packages index exist, "
                                       f"and does the user '{auth[0]}' have access?")
            elif result.status_code == 401:
                raise PackageLoadError("Authentication failed. Check your username/password combination.")
            return result.json()
        except requests.exceptions.ConnectionError:
            raise PackageLoadError('Failed to connect to Elasticsearch through Kibana proxy. Is it up?')

    def reload_installed_objects(self) -> List[InstalledObject]:
        """Fetches Package information from ES

        Performs a query based on the existing package manifest
        and loads all installed packages
        into self._installed_objects

        Returns:
            List of installed Objects
        """
        # should we instead perform inner hits query on nested object to get packages for current slug?
        query = {
            "query": {
                "term": {
                    "manifest.slug.keyword": {
                        "value": self.slug
                    }
                }
            }
        }
        result = None
        try:
            result = self.package_index_search(query, kibana_target=self.es_proxy_url, auth=self.auth)
        except PackageLoadError as e:
            self.logger.error(str(e))
        if not result:
            return []
        pkg = Package._parse_package_metadata(result)
        if not pkg:
            return []
        instobjs = [InstalledObject.from_kwargs(
            **iobj) for iobj in pkg.get('installed_objects')]
        self._installed_objects = instobjs
        return self._installed_objects

    @property
    def installed_objects(self) -> list:
        if not self._installed_objects and self.autoload_installed_objects:
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
            kibana_target: The URL to the Kibana instance your wish to connect to (E.G https://my_kibana.local:5601)
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
                data=json.dumps(mappings.PACKAGES_INDEX_MAPPING),
                auth=self.auth,
                headers={'content-type': 'application/json', 'kbn-xsrf': 'dynamite-nsm'},
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
        input_dict = self.__dict__
        overrides = input_dict.keys()
        for arg, val in kwargs.items():
            if arg in overrides:
                input_dict[arg] = val
        return input_dict

    @staticmethod
    def result_to_object(result: dict, tenant: Optional[str] = None) -> InstalledObject:
        """Takes an installation result output from Kibana API and returns an InstalledObject

        Args:
            result (dict): result from installation call to kibana
            tenant (Optional[str], optional): set space ID for the installed object instance. Defaults to None.

        Returns:
            InstalledObject: Instance representing the object that was installed.
        """
        obj = InstalledObject.from_installation_result(
            result, tenant=tenant)
        if tenant:
            obj.tenant = tenant
        return obj
    
    def uninstall(self, kibana_target: str, auth: Tuple[str, str], force: Optional[bool] = False) -> bool:
        """uninstalls a package from kibana

        Args:
            kibana_target: The URL to the Kibana instance your wish to connect to (E.G https://my_kibana.local:5601)
            auth: Authentication for kibana
            force: If True, packages with matching ID is uninstalled from all spaces.
                Defaults to True.

        Returns:
            True, if successfully uninstalled
        """
        statuses = []
        pb = progressbar.ProgressBar(widgets=PROGRESS_BAR_UNINSTALL_WIDGETS, maxval=len(self.installed_objects))
        pb.start()
        for i, iobj in enumerate(self.installed_objects):
            pb.update(i+1)
            url = f'{kibana_target}/api/saved_objects'
            del_url = f"{url}/{iobj.object_type}/{iobj.object_id}"
            if force:
                del_url += "?force=true"
            resp = requests.delete(del_url, auth=auth, verify=False, headers={
                'kbn-xsrf': 'true'})
            success = resp.status_code in range(200, 299) or resp.status_code == 404
            if success:
                self.deregister()
            else:
                raise PackageUninstallationError(f"Something went wrong trying to uninstall a package: "
                                                 f"{resp.json().get('message')}")
            statuses.append(success)
        return all(statuses)

    def deregister(self) -> bool:
        """De-registers a package from the dynamite-packages index

        Returns:
            If True, de-register succeeded.
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
            If True, register succeeded.
        """
        self.create_packages_index()
        package_id = uuid4()
        res = requests.post(f"{self.es_proxy_url}?method=POST&path={self.package_index_name}/_doc/{package_id}",
                            json=self.es_input(id=str(package_id)),
                            verify=False,
                            auth=self.auth,
                            headers={'kbn-xsrf': 'true'})
        return res.status_code in range(200, 299)

    @staticmethod
    def find_by_id(package_id: str, kibana_target: Optional[str] = None, username: Optional[str] = None,
                   password: Optional[str] = None) -> Optional[Package]:
        """Fetches an installed package by their id

        Args:
            kibana_target: The URL to the Kibana instance your wish to connect to (E.G https://my_kibana.local:5601)
            package_id (str): uuid for package (source id, not document id.)
            username: The username. Defaults to None.
            password: The password. Defaults to None.

        Raises:
            ValueError: Something went wrong performing search. e.g: ES is down
        Returns:
            A Package instance fetched by id or None if no package found

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
        result = Package.package_index_search(query, kibana_target, auth=(username, password))
        pkg = Package._parse_package_metadata(result)
        if not pkg:
            return
        manifest = PackageManifest(pkg.get('manifest'))
        inst_objs = [InstalledObject.from_kwargs(**iobj) for iobj in pkg.get('installed_objects')]
        package = Package(manifest, installed_objects=inst_objs, package_id=pkg.get('id'), kibana_target=kibana_target,
                          auth=(username, password))
        return package

    @staticmethod
    def find_by_slug(package_slug: str, kibana_target: Optional[str] = None, username: Optional[str] = None,
                     password: Optional[str] = None) -> Optional[Package]:
        """Find a package by its slug

        Args:
            kibana_target: The URL to the Kibana instance your wish to connect to (E.G https://my_kibana.local:5601)
            package_slug: Slug for package
            username: The username. Defaults to None.
            password: The password. Defaults to None.
        Raises:
            ValueError: Something went wrong performing search. e.g: ES is down
        """
        query = {
            "query": {
                "term": {
                    "manifest.slug.keyword": {
                        "value": package_slug,
                    }
                }
            }
        }
        result = Package.package_index_search(query, kibana_target, auth=(username, password))
        pkg = Package._parse_package_metadata(result)
        if not pkg:
            return
        manifest = PackageManifest(pkg.get('manifest'))
        inst_objs = [InstalledObject.from_kwargs(**iobj) for iobj in pkg.get('installed_objects')]
        package = Package(manifest, inst_objs, package_id=pkg.get('id'), kibana_target=kibana_target)
        return package

    @staticmethod
    def search_installed_packages(package_name=None, kibana_target: Optional[str] = None,
                                  username: Optional[str] = None, password: Optional[str] = None) -> Optional[list]:
        """
        Returns Packages with wildcard search on provided package name string,
            returns all packages if package name not supplied

        Args:
            kibana_target: The URL to the Kibana instance your wish to connect to (E.G https://my_kibana.local:5601)
            package_name ([str], optional): UUID of the package. Defaults to None.
            username: The username. Defaults to None.
            password: The password. Defaults to None.

        Returns:
            A list of Packages
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
                "match": {
                    "manifest.name": {
                        "query": package_name,
                        "minimum_should_match": 1
                    }
                }
            }
        result = Package.package_index_search(query, kibana_target, auth=(username, password))
        if not result:
            return None

        # If we want to just display the titles and num packages, we can pull from aggs result instead.
        packages_data = [r['_source'] for r in result['hits']['hits']]
        packages = []
        for pkg in packages_data:
            manifest = PackageManifest(pkg.get('manifest'))
            inst_objs = [InstalledObject.from_kwargs(
                **iobj) for iobj in pkg.get('installed_objects')]
            package = Package(manifest, inst_objs, package_id=pkg.get('id'), kibana_target=kibana_target)
            packages.append(package)
        return packages
