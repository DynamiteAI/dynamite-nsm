import logging
import subprocess

from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions


class OSPackageManager:
    """
    Interface for interacting with the operating systems package manager system
    Currently supports YUM/apt-get
    """

    def __init__(self, stdout=True, verbose=False):
        self.package_manager = self.detect_package_manager(verbose=verbose)
        self.verbose = verbose

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('OS_PACKAGE_MGR', level=log_level, stdout=stdout)

    @staticmethod
    def detect_package_manager(verbose=False):
        """
        Detect the POSIX package manager currently being used
        :return: The package manager command
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
            raise general_exceptions.InvalidOsPackageManagerDetectedError()

    def install_packages(self, packages):
        """
        Given a set of packages, installs the packages

        :param packages: Name of binary packages to install
        """
        flags = '-y'
        failed_packages = []
        if not self.package_manager:
            return False
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
            self.logger.error(
                "One or more packages failed to install install the following packages manually: {}".format(
                    failed_packages))
            raise general_exceptions.OsPackageManagerInstallError(
                "One or more packages failed to install install the following packages manually: {}".format(
                    failed_packages))

    def refresh_package_indexes(self):
        """
        Refresh the package cache
        """
        params = None
        if self.package_manager == 'apt-get':
            params = 'update'
        elif self.package_manager == 'yum':
            params = 'check-update'
        if not self.package_manager:
            return False
        if self.verbose:
            p = subprocess.Popen('{} {} &> /dev/null'.format(self.package_manager, params), shell=True)
        else:
            p = subprocess.Popen('{} {} &> /dev/null'.format(self.package_manager, params), shell=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate()
        if p.returncode not in [0, 100]:
            self.logger.error('Could not refresh package index via {}'.format(self.package_manager))
            raise general_exceptions.OsPackageManagerRefreshError(
                "OS package manager was unable to update; exited with {}".format(p.returncode))
