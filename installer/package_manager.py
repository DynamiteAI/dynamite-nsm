import subprocess


class OSPackageManager:

    def __init__(self):
        self.package_manager = self.detect_package_manager()

    @staticmethod
    def detect_package_manager():
        apt_get_p = subprocess.Popen('apt-get -h &>/dev/null', shell=True)
        apt_get_p.communicate()
        yum_p = subprocess.Popen('yum -h &>/dev/null', shell=True)
        yum_p.communicate()
        if apt_get_p.returncode == 0:
            return 'apt-get'
        elif yum_p.returncode == 0:
            return 'yum'

    def install_packages(self, packages):
        flags = ''
        if self.package_manager == 'yum':
            flags = '-y'
        subprocess.call('{} install {} {}'.format(self.package_manager, ' '.join(packages), flags), shell=True)