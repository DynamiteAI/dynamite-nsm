import subprocess


class OSPackageManager:
    """
    Interface for interacting with the operating systems package manager system
    Currently supports YUM/apt-get
    """
    def __init__(self):
        self.package_manager = self.detect_package_manager()

    @staticmethod
    def detect_package_manager():
        """
        Detect the POSIX package manager currently being used
        :return: The package manager command
        """
        apt_get_p = subprocess.Popen('apt-get -h &> /dev/null', shell=True)
        apt_get_p.communicate()
        yum_p = subprocess.Popen('yum -h &> /dev/null', shell=True)
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
        p = subprocess.Popen('{} {} install {}'.format(self.package_manager, flags, ' '.join(packages)),
                             shell=True)
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
        p = subprocess.Popen('{} {} &> /dev/null'.format(self.package_manager, params), shell=True)
        p.communicate()
        return p.returncode == 0 or p.returncode == 100
