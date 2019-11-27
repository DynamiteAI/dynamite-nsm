import sys
import subprocess
from dynamite_nsm import package_manager
INSTALL_DIRECTORY = '/opt/dynamite/jupyterhub/'


class JupyterInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        pass

    @staticmethod
    def install_dependencies():
        """
        Install the required dependencies required by Zeek

        :return: True, if all packages installed successfully
        """
        pacman = package_manager.OSPackageManager()
        if not pacman.refresh_package_indexes():
            return False
        packages = None
        pacman.refresh_package_indexes()
        print(pacman.package_manager + ' TEST')
        if pacman.package_manager == 'apt-get':
            packages = ['python3', 'python3-pip', 'nodejs', 'npm']
        elif pacman.package_manager == 'yum':
            pacman.install_packages(['curl', 'gcc-c++', 'make'])
            p = subprocess.Popen('curl --silent --location https://rpm.nodesource.com/setup_10.x | sudo bash -',
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, close_fds=True)
            p.communicate()
            if p.returncode != 0:
                sys.stderr.write('[-] Could not install node rpm.\n')
                return False
            pacman.install_packages(['nodejs', 'python36'])
        if packages:
            return pacman.install_packages(packages)
        return False


print('RESULT: {}'.format(JupyterInstaller.install_dependencies()))