import logging
import subprocess
from typing import List, Optional

from dynamite_nsm.logger import get_logger


class OsPackageManagerNotDetectedError(Exception):
    def __init__(self):
        msg = "Did not detect a valid OS package manager; currently APT-GET & YUM are supported."
        super(OsPackageManagerNotDetectedError, self).__init__(msg)


class OSPackageManager:
    """
    Interface for interacting with the operating systems package manager system
    Currently supports YUM/apt-get
    """

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False):
        """
        Args:
            stdout: Print the output to console
            verbose: Include detailed debug messages
        """
        self.package_manager = self.detect_package_manager(verbose=verbose)
        self.verbose = verbose

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('package.manager', level=log_level, stdout=stdout)

    @staticmethod
    def detect_package_manager(verbose: Optional[bool] = False) -> str:
        """Detect the POSIX package manager currently being used
        Args:
            verbose: Include detailed debug messages
        Returns:
             The package manager command (either apt-get or yum)
        """
        if verbose:
            apt_get_p = subprocess.Popen('apt-get -h &> /dev/null', shell=True)
        else:
            apt_get_p = subprocess.Popen('apt-get -h &> /dev/null', shell=True,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        apt_get_p.communicate()
        if verbose:
            yum_p = subprocess.Popen('yum -h &> /dev/null', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            yum_p = subprocess.Popen('yum -h &> /dev/null', shell=True)
        yum_p.communicate()
        if apt_get_p.returncode == 0:
            return 'apt-get'
        elif yum_p.returncode == 0:
            return 'yum'
        else:
            raise OsPackageManagerNotDetectedError()

    def install_packages(self, packages: List[str]) -> None:
        """Given a set of packages, installs the packages
        Args:
            packages: Name of binary packages to install
        Returns:
            None
        """
        flags = '-y'
        failed_packages = []
        if not self.package_manager:
            return None
        for package in packages:
            self.logger.info('Installing {}'.format(package))
            if self.verbose:
                p = subprocess.Popen('{} {} install {}'.format(self.package_manager, flags, package),
                                     shell=True)
            else:
                p = subprocess.Popen('{} {} install {}'.format(self.package_manager, flags, package),
                                     shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.communicate()
            if p.returncode not in [0, 100]:
                # Interestingly enough apt-get can return 100s if https isn't forced
                # https://stackoverflow.com/questions/38002543/apt-get-update-returned-a-non-zero-code-100
                self.logger.warning('{} failed to install.'.format(package))
                failed_packages.append(package)
        if failed_packages:
            self.logger.warning(
                f'One or more packages failed to install you may need to install the following packages '
                f'manually: {failed_packages}.')

    def refresh_package_indexes(self) -> None:
        """Refresh the package cache
        Args:

        Returns:
            None
        """
        params = None
        if self.package_manager == 'apt-get':
            params = 'update'
        elif self.package_manager == 'yum':
            params = 'check-update'
        if not self.package_manager:
            return
        if self.verbose:
            p = subprocess.Popen(f'{self.package_manager} {params} &> /dev/null', shell=True)
        else:
            p = subprocess.Popen(f'{self.package_manager} {params} &> /dev/null', shell=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate()
        if p.returncode not in [0, 100]:
            self.logger.warning(f'Could not refresh package index via {self.package_manager}')
