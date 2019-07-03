import subprocess


class OSPackageManager:

    def __init__(self):
        self.package_manager = self.detect_package_manager()

    @staticmethod
    def detect_package_manager():
        """
        Detect the POSIX package manager currently being used
        :return: The package manager command
        """
        apt_get_p = subprocess.Popen('apt-get -h &>/dev/null', shell=True)
        apt_get_p.communicate()
        yum_p = subprocess.Popen('yum -h &>/dev/null', shell=True)
        yum_p.communicate()
        if apt_get_p.returncode == 0:
            return 'apt-get'
        elif yum_p.returncode == 0:
            return 'yum'

    def install_packages(self, packages):
        """
        Given a set of packages, installs the packages
        :param packages: Name of binary packages to install
        """
        flags = ''
        if self.package_manager == 'yum':
            flags = '-y'
        subprocess.call('{} install {} {}'.format(self.package_manager, ' '.join(packages), flags), shell=True)