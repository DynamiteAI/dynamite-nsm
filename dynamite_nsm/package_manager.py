import subprocess


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
        yum_p = subprocess.Popen('yum -h &> /dev/null', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        yum_p.communicate()
        if apt_get_p.returncode == 0:
            return 'apt-get'
        elif yum_p.returncode == 0:
            return 'yum'
        else:
            return None

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
        return p.returncode == 0

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
        return p.returncode == 0 or p.returncode == 100
