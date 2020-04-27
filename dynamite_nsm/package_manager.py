import subprocess
from dynamite_nsm import exceptions as general_exceptions


class OSPackageManager:
    """
    Interface for interacting with the operating systems package manager system
    Currently supports YUM/apt-get
    """

    def __init__(self, verbose=False):
        self.package_manager = self.detect_package_manager(verbose=verbose)
        self.verbose = verbose

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
        if not self.package_manager:
            return False
        if self.verbose:
            p = subprocess.Popen('{} {} install {}'.format(self.package_manager, flags, ' '.join(packages)),
                                 shell=True)
        else:
            p = subprocess.Popen('{} {} install {}'.format(self.package_manager, flags, ' '.join(packages)),
                                 shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate()
        if p.returncode not in [0, 100]:
            # Interestingly enough apt-get can return 100s if https isn't forced
            # https://stackoverflow.com/questions/38002543/apt-get-update-returned-a-non-zero-code-100
            raise general_exceptions.OsPackageManagerInstallError(
                "OS package manager exited with {}; One or more packages was not installed".format(p.returncode))

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
            raise general_exceptions.OsPackageManagerRefreshError(
                "OS package manager was unable to update; exited with {}".format(p.returncode))
