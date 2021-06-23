from __future__ import annotations

import os
import logging
import mimetypes
import tarfile
import requests
from getpass import getpass
from datetime import datetime
from io import BytesIO, IOBase
from typing import AnyStr, Dict, Optional, Tuple, IO, List, Union
from itertools import chain
from urllib.parse import urlparse

import progressbar
from tabulate import tabulate

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.kibana.package import schemas
from dynamite_nsm import exceptions as generic_exceptions
from dynamite_nsm.services.kibana.package import package as package_objects


class SavedObjectsManager:
    def __init__(self, username: Optional[str] = None, password: Optional[str] = None, target: Optional[str] = None,
                 stdout: Optional[bool] = True, verbose: Optional[bool] = False):
        """Initializes the SavedObjectsManager
        Args:
            username: A Kibana user. Defaults to None.
            password: The corresponding password. Defaults to None.
            stdout: Print the output to console
            verbose: Include detailed debug messages
            target: The full URL to the Kibana instance your wish to connect to (E.G https://my_kibana.local:5601)
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('kibana.package', level=log_level, stdout=stdout)
        self.verbose = verbose
        self._installed_packages = None
        self._kibana_url = target
        self.username, self.password = self.get_kibana_auth_securely(username, password)
        if not self.validate_kibana_target(target):
            self.logger.error(f'{target} is invalid. Please use a different Kibana url.')
            exit(1)

    @property
    def kibana_url(self) -> str:
        if not self._kibana_url:
            self._kibana_url = package_objects.get_kibana_url()
        return self._kibana_url

    def validate_kibana_target(self, target: Optional[str] = None) -> bool:
        try:
            targ = target or self.kibana_url
            result = urlparse(targ)
            return all([result.scheme, result.netloc])
        except Exception as e:
            self.logger.error(f"Could not validate kibana target url {self.kibana_url}")
            if self.verbose:
                self.logger.debug(e)
                return False
        return True

    def check_kibana_connection(self, username: str, password: str) -> bool:
        auth = (username, password)
        try:
            if self.verbose:
                self.logger.info('Checking if Kibana API is up.')
            resp = requests.get(f'{self.kibana_url}/api/status', auth=auth)
            if resp.status_code == 200:
                status_state = resp.json().get('status', {'overall': {'state': 'unknown'}}).get('overall').get('state')
                if self.verbose:
                    self.logger.info(f'Kibana status: {status_state}')
        except requests.exceptions.ConnectionError as e:
            self.logger.exception(e)
            return False
        return True

    @staticmethod
    def get_kibana_auth_securely(username: Optional[str] = None, password: Optional[str] = None) -> Tuple[str, str]:
        """Gets kibana auth info from user input
        Args:
            username: The username. Defaults to None.
            password: The password. Defaults to None.

        Returns:
            Auth tuple
        """
        # need to be able to provide these as parameters to the cmd
        if not username:
            username = input("Kibana Username: ")
        if not password:
            password = getpass("Kibana Password: ")
        return username, password

    def _process_package_installation_results(self,
                                              package: package_objects.Package,
                                              kibana_response: dict,
                                              tenant: Optional[str] = "") -> bool:

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
            installed_obj = package.result_to_object(installed, tenant=tenant)
            package.installed_objects.append(installed_obj)
        return success

    def _select_packages_for_uninstall(self, package_name) -> Optional[List[package_objects.Package]]:
        invalid_selection_msg = "Not a valid selection"
        non_integer_selection_msg = "Selections must be integers"
        
        installed_packages = package_objects.Package.search_installed_packages(package_name,
                                                                               kibana_target=self.kibana_url,
                                                                               username=self.username,
                                                                               password=self.password)
        if not installed_packages:
            self.logger.error("Could not find any packages to uninstall.")
            return
        else:
            if len(installed_packages) > 1 or package_name:
                print("Select a package to uninstall: ")

                for package in installed_packages:
                    idx = installed_packages.index(package)
                    if package.manifest.description and len(package.manifest.description) > 50:
                        desc = f"{package.manifest.description[:50]}.."
                    else:
                        desc = package.manifest.description
                    tenants = set([iobj.tenant for iobj in package.installed_objects])
                    if tenants:
                        tenants = ", ".join(tenants)
                    lbb = utilities.PrintDecorations.colorize('[', 'bold')
                    rbb = utilities.PrintDecorations.colorize(']', 'bold')
                    package_name = utilities.PrintDecorations.colorize(package.manifest.name, 'bold')
                    plinepadding = ' ' * (len(str(idx)) + 2)
                    package_line = f"{lbb}{idx + 1}{rbb} {package_name} - [{tenants}]\n{plinepadding} * {desc}"
                    print(package_line)
            else:
                pkg = installed_packages[0]
                package_name = utilities.PrintDecorations.colorize(pkg.manifest.name, 'bold')
                print(f"{utilities.PrintDecorations._COLOR_RESET}Preparing package {package_name} for uninstall..")
        print()
        selections = []
        if package_name and len(installed_packages) < 2:
            selections = ['1']
        while not bool(selections):
            _selections = input('Select package(s) to uninstall (For example: "1 2 3 5 8"): ')
            _selections = _selections.split(" ")
            try:
                for sel in _selections:
                    sel = int(sel)
                    if sel - 1 not in range(0, len(installed_packages)):
                        raise ValueError(invalid_selection_msg)
                    selections.append(sel)
            except ValueError as e:
                if str(e) == invalid_selection_msg:
                    numpkgs = len(installed_packages)
                    rangemsg = ""
                    if numpkgs > 1:
                        rangemsg = f". Must be 1-{numpkgs}"
                    self.logger.error(f"{invalid_selection_msg}{rangemsg}")
                else:
                    self.logger.error(non_integer_selection_msg)
                continue
        packages = [installed_packages[int(selection) - 1] for selection in selections]
        return packages

    def browse_saved_objects(self, saved_object_type: Optional[str] = None) -> requests.Response:
        """Browse saved packages in kibana whether or not they are part of a dynamite package.
        Args:
            saved_object_type: The type of packages to limit the search to. Defaults to None.

        Returns:
            requests.Response: data returned from kibana
        """

        if saved_object_type:
            resp = requests.get(
                f'{self.kibana_url}/api/saved_objects/_find?type={saved_object_type}',
                auth=(self.username, self.password))
        else:
            resp = requests.get(
                f'{self.kibana_url}/api/saved_objects/_find'
                f'?type=dashboard'
                f'&type=index-pattern'
                f'&type=visualization'
                f'&type=search'
                f'&type=config'
                f'&type=timelion-sheet',
                auth=(self.username, self.password))
        if resp.status_code not in range(200, 299):
            self.logger.error(
                f'Kibana endpoint returned a {resp.status_code} - {resp.text}')
            # TODO raise exception
        return resp

    def uninstall_kibana_saved_objects(self, packages: List[package_objects.Package],
                                       force: Optional[bool] = False) -> None:
        """Uninstall packages and their saved packages from kibana

        Args:
            packages: A list of packages to uninstall
            force: force uninstall from all spaces?
        """
        self.logger.info(f"Preparing {len(packages)} for uninstall.")
        for i, package in enumerate(packages):
            package.reload_installed_objects()
            try:
                uninstalled = package.uninstall(self.kibana_url, auth=(self.username, self.password))
                if uninstalled:
                    self.logger.info(f"Uninstalled {package.manifest.name} successfully.")
            except package_objects.PackageUninstallationError as e:
                self.logger.exception(e)
                self.logger.error(f"Could not uninstall package {package.id} ({package.manifest.name})")

    def logout_authenticated_session(self, authenticated_session):
        authenticated_session.post(f'{self.kibana_url}/auth/logout', headers={'kbn-xsrf': 'true'})

    def get_authenticated_session(self, username, password):
        session = requests.Session()
        login_resp = session.post(f'{self.kibana_url}/auth/login', data={
                'username': username,
                'password': password
            }, headers={'kbn-xsrf': 'true'})
        if login_resp.status_code not in range(200, 299):
            self.logger.error("Failed to authenticate to kibana with provided credentials.")
            return None
        return session

    def get_current_tenant(self, authenticated_session):
        session = authenticated_session
        if not session:
            return None
        resp = session.get(f"{self.kibana_url}/api/v1/multitenancy/tenant")
        return resp.text

    def switch_tenant(self, tenant_name, username, authenticated_session):
        tenant_name = self.parse_tenant(tenant_name)
        authenticated_session.post(f"{self.kibana_url}/api/v1/multitenancy/tenant", data={
            "tenant": tenant_name,
            "username": username
        }, headers={'kbn-xsrf': 'true'})
        # things get weird without this GET.
        curtenant = authenticated_session.get(f"{self.kibana_url}/api/v1/multitenancy/tenant")
        return curtenant.text == tenant_name

    def parse_tenant(self, tenant: str):
        GLOBAL_TENANT = ""
        PRIVATE_TENANT = "__user__"
        if tenant:
            if tenant.lower() in ["private", "private_tenant", "user"]:
                tenant = PRIVATE_TENANT
            if tenant.lower() in ["global", "global_tenant"]:
                tenant = GLOBAL_TENANT
        else:
            tenant = GLOBAL_TENANT
        return tenant

    def import_kibana_saved_objects(self, kibana_objects_file: IO[AnyStr],
                                    tenant: Optional[str] = None,
                                    overwrite: Optional[bool] = True,
                                    create_copies: Optional[bool] = False) -> Dict:
        """Import saved packages into kibana from a package file

        Args:
            kibana_objects_file: the file to parse and install
            tenant: name of the tenant to install the package(s) to. Defaults to None.
            overwrite: If True, overwrite existing ids. Defaults to True.
            create_copies: create copies if an object exists with the same id?. Defaults to False.

        Raises:
            ValueError: Something went wrong

        Returns:
            Response from Kibana
        """
        auth = self.get_kibana_auth_securely(self.username, self.password)
        self.check_kibana_connection(*auth)
        session = self.get_authenticated_session(*auth)
        originaltenant = self.get_current_tenant(session)

        #  unsure why, but when you select the global tenant it just sends an empty string.
        if tenant:
            tenant = self.parse_tenant(tenant)
        url = f'{self.kibana_url}/api/saved_objects/_import'
        # switch our session to the appropriate tenant.
        self.switch_tenant(tenant, auth[0], session)
        if all([overwrite, create_copies]):
            raise ValueError(
                "createNewCopies and overwrite cannot be used together.")

        params = {'overwrite': overwrite, 'createNewCopies': create_copies}

        # TODO: Catch connection denied when kibana is down and handle/inform user gracefully
        kibana_objects_file.seek(0)
        if isinstance(kibana_objects_file, IOBase):
            req_data = {'file': ('dynamite_import.ndjson', kibana_objects_file)}
        else:
            req_data = {'file': kibana_objects_file}
        resp = session.post(url, params=params, auth=auth, files=req_data, headers={'kbn-xsrf': 'true'})
        if resp.status_code not in range(200, 299):
            self.logger.error(f'Kibana endpoint returned a {resp.status_code} - {resp.text}')
            # TODO raise exception
        self.switch_tenant(originaltenant, auth[0], session)
        return resp.json()

    def install(self, path: str, ignore_warnings: Optional[bool] = False, tenant: Optional[str] = "") -> bool:
        """Install a package. A package can be given as an archive or directory.
            A package must contain one or more ndjson files and a manifest.json

        Args:
            ignore_warnings: If True, the user won't be given a warning prompt if package will be overwritten.
            path: path to the file or folder of files
            tenant: The name of the tenant to install the package to.

        Returns:
            None
        """
        if tenant:
            available_tenants = self.list_tenants()
            at_names = [t['name'] for t in available_tenants]
            convenience_tenants = ["private", "global"]
            tenants = set(chain(at_names, convenience_tenants))

            if tenant not in tenants:
                self.logger.error(f'Tenant "{tenant}" is not a valid tenant, choose from: [{", ".join(tenants)}]')
                return False

        def handle_archive(fp: str, user: str, passwd: str, tenant: Optional[str] = "") -> package_objects.Package:
            """
            Handle Kibana package encapsulated within a tar.gz archive
            Args:
                fp: The path to the Kibana package archive
                user: A valid ES user
                passwd: A valid ES password
            Returns:
                None
            """
            tar = tarfile.open(fp)
            _manifest = tar.extractfile('manifest.json')
            _manifest = package_objects.PackageManifest(_manifest.read().decode('utf8'))
            _package = package_objects.Package(_manifest,
                                               kibana_target=self.kibana_url,
                                               autoload_installed_objects=False)
            _package.create_packages_index()
            # check if package exists already.
            existing = package_objects.Package.find_by_slug(
                package_slug=_package.manifest.create_slug(), kibana_target=self.kibana_url, username=user,
                password=passwd)
            if existing and not ignore_warnings:
                rm_existing = input(
                    f"A Package titled {existing.manifest.name} is already installed, "
                    "do you want to uninstall it? [y/n]: ") in "yY"
                if rm_existing:
                    if not user or not passwd:
                        user, passwd = self.get_kibana_auth_securely(user, passwd)
                    remove_success = existing.uninstall(
                        self.kibana_url, auth=(user, passwd), force=True)
                    if remove_success:
                        self.logger.info(
                            f"Successfully removed existing package {existing.manifest.name}.")
            for member in _manifest.file_list:
                # should we validate the json before sending it up to kibana?
                kibana_objects_file = BytesIO(
                    tar.extractfile(member).read())
                result = self.import_kibana_saved_objects(kibana_objects_file=kibana_objects_file, tenant=tenant)
                kibana_objects_file.close()
                if tenant:
                    if tenant == "__user__":
                        tenant = f"private: {user}"
                else:
                    tenant = "global"
                if not self._process_package_installation_results(_package, result, tenant):
                    self.logger.debug(_package, result)
                    raise generic_exceptions.InstallError(f'{_package.id} failed to install.')
            return _package

        def handle_file(fp, user: str, passwd: str) -> None:
            with open(fp, 'r') as kibana_objects_file:
                result = self.import_kibana_saved_objects(kibana_objects_file=kibana_objects_file)
                installation_statuses.append(
                    self._process_package_installation_results(package, result))

        if not path:
            self.logger.error('You must enter a path to the package you wish to install.')
            return False
        elif not os.path.exists(path):
            self.logger.error(f'This path does not exist: {path}')
            return False
        self.logger.info('Checking connection to Kibana.')
        self.check_kibana_connection(self.username, self.password)
        is_folder = os.path.isdir(path)
        if tenant:
            tenant = self.parse_tenant(tenant)
        file_paths = []
        if not is_folder:
            file_paths = [path]
        else:
            # check for installable items by extension, they will be verified by mimetype later.
            acceptable_extensions = ['tar.xz', 'tar.gz']
            for itm in os.listdir(path):
                for ex in acceptable_extensions:
                    if itm.endswith(ex):
                        file_paths.append(f"{path}{itm}")
                        break
            self.logger.info(f"Found {len(file_paths)} packages to install.")
        for file_path in file_paths:
            installation_statuses = []
            file_path = os.path.abspath(file_path)
            # check mimetype of the file to determine how to proceed
            filetype, encoding = mimetypes.MimeTypes().guess_type(file_path)
            # default to orphan package in case of install from .ndjson
            manifest = package_objects.PackageManifest(schemas.ORPHAN_OBJECT_PACKAGE_MANIFEST_DATA)
            package = package_objects.Package(manifest, kibana_target=self.kibana_url)

            if filetype == 'application/x-tar' or encoding == 'gzip':
                file_path = os.path.abspath(file_path)
                # check mimetype of the file to determine how to proceed
                self.logger.info(f'Installing from TAR archive: {file_path}.')
                package = handle_archive(file_path, self.username, self.password, tenant=tenant)
            # Should we remove this and ONLY install validatable packages?
            elif filetype in ('application/json', 'text/plain') and file_path.endswith('ndjson'):
                handle_file(file_path, self.username, self.password)
            else:
                self.logger.error(
                    "Files must be one of: .ndjson, .json, .tar.xz, .tar.gz")
                # TODO raise exception

            if not all(installation_statuses):
                self.logger.error(f'{package.manifest.name} installation failed.')
                if not self.verbose:
                    self.logger.info('Use --verbose flag to see more error detail.')
            else:
                package.register()
                self.logger.info(f"{package.manifest.name} installation succeeded!")
        return True

    def list(self, pretty: Optional[bool] = True) -> Optional[Union[str, List]]:
        """List packages currently installed for this instance
            Args:
                pretty: If true, packages will be enumerated in a tabulated form
        """
        try:
            packages = package_objects.Package.search_installed_packages(kibana_target=self.kibana_url,
                                                                         username=self.username, password=self.password)
        except package_objects.PackageLoadError as e:
            self.logger.error(e)
            return None
        if not packages:
            self.logger.error("Could not find any installed packages.")
            return None
        if pretty:
            headers = ["Package Id", "Package Name", "Package Author", "Objects"]
            table = []
            for package in packages:
                row = [package.id, package.manifest.name, package.manifest.author]
                object_table_headers = ['Object Name', 'Object Type', 'Tenant']
                object_table = []
                for obj in package.installed_objects:
                    if not isinstance(obj, package_objects.InstalledObject):
                        continue

                    obj_tbl_row = [obj.title, obj.object_type, obj.tenant]
                    object_table.append(obj_tbl_row)
                row.append(tabulate(object_table, headers=object_table_headers, tablefmt="fancy_grid"))
                table.append(row)
            return tabulate(table, headers=headers, tablefmt="fancy_grid")
        else:
            data = []
            for package in packages:
                data.append(package.es_input())
            return data

    def list_tenants(self, pretty: Optional[bool] = False) -> Union[str, List]:
        url = f'{package_objects.Package.build_proxy_url_from_target(self.kibana_url)}'\
               '?path=_opendistro/_security/api/tenants&method=GET'
        resp = requests.post(url, auth=(self.username, self.password), headers={'kbn-xsrf': 'true'})
        if resp.status_code == 403:
            self.logger.error(resp.json().get('message'))
            exit(0)
        fetched_data = resp.json()
        table = []
        headers = ["Name", "Description", "Reserved", "Hidden", "Static"]
        for tenant_name, tenant_data in fetched_data.items():
            if pretty:
                table.append([
                    tenant_name,
                    tenant_data.get('description'),
                    tenant_data.get('reserved'),
                    tenant_data.get('hidden'),
                    tenant_data.get('static')
                ])
            else:
                tenant_data.update({"name": tenant_name})
                table.append(tenant_data)
        if pretty:
            return tabulate(table, headers=headers, tablefmt="fancy_grid")
        else:
            return table
    
    def list_saved_objects(self, saved_object_type: Optional[str] = None,
                           pretty: Optional[bool] = False) -> Union[str, List]:
        """List the saved_objects currently installed irrespective of which "package" the belong too

        Args:
            saved_object_type: Either ['config', 'dashboard', 'index-pattern', 'search', 'visualization'].
            pretty: If true, packages will be enumerated in a tabulated form
        """

        fetched_data = self.browse_saved_objects(saved_object_type=saved_object_type).json()
        table = []
        headers = ["Title", "Object Type", "Object ID"]
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

    def uninstall(self, username: Optional[str] = None, password: Optional[str] = None,
                  package_name: Optional[str] = None, package_id: Optional[str] = None,
                  remove_from_all_spaces: Optional[bool] = False) -> None:
        """Uninstall packages from instance

        Args:
            username: kibana auth username. Defaults to None.
            password: kibana auth password. Defaults to None.
            package_name: name of the package to search for.
            package_id: A unique identifier associated with the package
            remove_from_all_spaces: force removal from all spaces. Defaults to False.
        """
        if not self.username or not self.password:
            self.username, self.password = self.get_kibana_auth_securely(username, password)
        if package_id and package_name:
            self.logger.error(
                "Package Name and Package Id cannot be used together")
            return

        try:
            if not package_id:
                to_uninstall = self._select_packages_for_uninstall(package_name)
                if not to_uninstall:
                    self.logger.error(f"Could not find any packages for query: {package_name}")
                    return
            else:
                to_uninstall = package_objects.Package.find_by_id(package_id, kibana_target=self.kibana_url,
                                                                  username=self.username, password=self.password)
                if not to_uninstall:
                    self.logger.error(
                        f"Could not find package with id {package_id}")
                    exit(0)
                to_uninstall = [to_uninstall]
        except package_objects.PackageLoadError as e:
            self.logger.error(e)
            return
        
        force = bool(remove_from_all_spaces)
        self.check_kibana_connection(username, password)
        self.uninstall_kibana_saved_objects(to_uninstall, force=force)
