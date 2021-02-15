import logging
import tarfile
from typing import Callable, List, Optional

from dynamite_nsm import const
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm import package_manager
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger


class BaseInstallManager:

    def __init__(self, name, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.stdout = stdout
        self.verbose = verbose
        self.logger = get_logger(str(name).upper(), level=log_level, stdout=stdout)

    @staticmethod
    def download_from_mirror(mirror_path: str, fname: str, stdout: Optional[bool] = True,
                             verbose: Optional[bool] = True) -> None:
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('BASESVC', level=log_level, stdout=stdout)

        with open(mirror_path) as mirror_f:
            res, err = None, None
            for url in mirror_f.readlines():
                logger.info("Downloading {} from {}".format(fname, url))
                try:
                    res = utilities.download_file(url, fname, stdout=stdout)
                except Exception as e:
                    res, err = False, e
                    logger.warning(f'Failed to download {fname} from {url}; {e}')
                if res:
                    break
            if not res:
                raise general_exceptions.DownloadError(
                    f'General error while attempting to download {fname} from all mirrors.')

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

    def install_dependencies(self, apt_get_packages: Optional[List] = None, yum_packages: Optional[List] = None,
                             pre_install_function: Optional[Callable] = None):
        pacman = package_manager.OSPackageManager(stdout=self.stdout, verbose=self.verbose)
        if pacman.package_manager == 'apt-get':
            self.logger.info('apt-get detected. We will use this package manager to install dependencies.')
            packages = apt_get_packages
        elif pacman.package_manager == 'yum':
            self.logger.info('yum detected. We will use this package manager to install dependencies.')
            packages = yum_packages
        else:
            raise general_exceptions.InvalidOsPackageManagerDetectedError()
        self.logger.info('Refreshing package indexes')
        if pre_install_function:
            self.logger.info('Running pre-installation function.')
            pre_install_function(pacman.package_manager)
        pacman.refresh_package_indexes()
        self.logger.debug(f'Packages: {packages}')
        if packages:
            self.logger.info(f'Installing {len(packages)} new packages.')
            pacman.install_packages(packages)
