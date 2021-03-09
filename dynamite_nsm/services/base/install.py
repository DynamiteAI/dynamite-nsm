import os
import shutil
import logging
import tarfile
from typing import Callable, List, Optional, Tuple, Union

from dynamite_nsm import const
from dynamite_nsm import package_manager
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions


class NetworkInterfaceNotFound(Exception):
    """
    Thrown when attempting to disable a non-existing interface
    """

    def __init__(self, interfaces: Union[str, List]):
        """
        :param interfaces: A network interface
        """
        msg = f'Network interface(s) does not exist: {interfaces}.'
        super(NetworkInterfaceNotFound, self).__init__(msg)


class BaseInstallManager:

    def __init__(self, name: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.stdout = stdout
        self.verbose = verbose
        self.logger = get_logger(str(name).upper(), level=log_level, stdout=stdout)
        utilities.makedirs(const.PID_PATH, exist_ok=True)
        utilities.set_ownership_of_file(const.PID_PATH, user='dynamite', group='dynamite')

    @staticmethod
    def create_update_env_variable(name: str, value: str):
        name = str(name)
        value = str(value)
        env_file_path = f'{const.CONFIG_PATH}/environment'
        if not os.path.exists(env_file_path):
            with open(env_file_path, 'w') as env_f:
                env_f.write('')

        overwrite_line_no = -1
        with open(env_file_path) as env_fr:
            read_lines = env_fr.readlines()
            for idx, line in enumerate(read_lines):
                if str(line).startswith(name):
                    overwrite_line_no = idx
                    break
        if overwrite_line_no == -1:
            with open(env_file_path, 'a') as env_fa:
                env_fa.write(f'{name}={value}\n')
        else:
            if value.endswith('\n'):
                read_lines[overwrite_line_no] = f'{name}={value}'
            else:
                read_lines[overwrite_line_no] = f'{name}={value}\n'
            with open(env_file_path, 'w') as env_fw:
                env_fw.writelines(read_lines)

    @staticmethod
    def download_from_mirror(mirror_path: str, stdout: Optional[bool] = True, verbose: Optional[bool] = True
                             ) -> Tuple[str, str, Optional[str]]:
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('DOWNLOAD', level=log_level, stdout=stdout)

        with open(mirror_path) as mirror_f:
            res, err = None, None
            for mirror in mirror_f.readlines():
                try:
                    url, archive_name, dir_name = [token.strip() for token in mirror.split(',')]
                except ValueError:
                    url = mirror
                    archive_name = os.path.basename(url)
                    dir_name = None
                logger.info("Downloading {} from {}".format(archive_name, url))
                fqdn_dir_name = f'{const.INSTALL_CACHE}/{str(dir_name)}'
                if os.path.exists(fqdn_dir_name):
                    shutil.rmtree(fqdn_dir_name, ignore_errors=True)
                try:
                    res = utilities.download_file(url, archive_name, stdout=stdout)
                except Exception as e:
                    res, err = False, e
                    logger.warning(f'Failed to download {archive_name} from {url}; {e}')
                if res:
                    break
            if not res:
                raise general_exceptions.DownloadError(
                    f'General error while attempting to download {archive_name} from all mirrors.')
            return url, archive_name, dir_name

    @staticmethod
    def extract_archive(archive_path: str) -> None:
        try:
            tf = tarfile.open(archive_path)
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            raise general_exceptions.ArchiveExtractionError(
                f'Could not extract {archive_path} archive to {const.INSTALL_CACHE}; {e}')
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                f'General error while attempting to extract {archive_path} archive; {e}')

    @staticmethod
    def get_mirror_info(mirror_path: str) -> Tuple[str, str, Optional[str]]:
        with open(mirror_path) as mirror_f:
            for mirror in mirror_f.readlines():
                try:
                    url, archive_name, dir_name = [token.strip() for token in mirror.split(',')]
                except ValueError:
                    url = mirror
                    archive_name = os.path.basename(url)
                    dir_name = None

        return url, archive_name, dir_name

    @staticmethod
    def validate_capture_network_interfaces(network_interfaces: List[str]) -> bool:
        for interface in network_interfaces:
            if interface not in utilities.get_network_interface_names():
                return False
        return True

    def copy_file_or_directory_to_destination(self, file_or_dir: str, destination_file_or_dir: str):
        file_or_dir = file_or_dir.rstrip('/')
        destination_location = f'{destination_file_or_dir}/{os.path.basename(file_or_dir)}'
        if os.path.isdir(file_or_dir):
            utilities.makedirs(destination_location, exist_ok=True)
            self.logger.debug(f'Creating directory: {destination_location}')
            try:
                self.logger.debug(f'Copying directory {file_or_dir} -> {destination_location}')
                utilities.copytree(file_or_dir, destination_location)
            except shutil.Error as e:
                if 'exist' in str(e):
                    self.logger.warning(f'{destination_file_or_dir} directory already exists. Skipping.')
                else:
                    raise e
        else:
            try:
                self.logger.debug(f'Copying file {file_or_dir} -> {destination_file_or_dir}')
                shutil.copy(file_or_dir, destination_file_or_dir)
            except shutil.Error as e:
                if 'exist' in str(e):
                    self.logger.warning(f'{destination_file_or_dir} file already exists. Skipping.')
                else:
                    raise e

    def install_dependencies(self, apt_get_packages: Optional[List] = None, yum_packages: Optional[List] = None,
                             pre_install_function: Optional[Callable] = None):
        pacman = package_manager.OSPackageManager(stdout=self.stdout, verbose=self.verbose)
        packages = []
        if pacman.package_manager == 'apt-get':
            self.logger.info('apt-get detected. We will use this package manager to install dependencies.')
            packages = apt_get_packages
        elif pacman.package_manager == 'yum':
            self.logger.info('yum detected. We will use this package manager to install dependencies.')
            packages = yum_packages
        self.logger.info('Refreshing package indexes')
        if pre_install_function:
            self.logger.info('Running pre-installation function.')
            pre_install_function(pacman.package_manager)
        pacman.refresh_package_indexes()

        self.logger.debug(f'Packages: {packages}')
        if packages:
            self.logger.info(f'Installing {len(packages)} new packages.')
            pacman.install_packages(packages)
