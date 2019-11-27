import os
import sys
import shutil
import subprocess
from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
INSTALL_DIRECTORY = '/opt/dynamite/jupyterhub/'
SDK_HOME = '/home/jupyter/dynamite-sdk/'


class JupyterInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        self.install_directory = install_directory

    @staticmethod
    def install_dependencies(stdout=False):
        """
        Install the required dependencies required by Jupyterhub

        :return: True, if all packages installed successfully
        """
        pacman = package_manager.OSPackageManager()
        if not pacman.refresh_package_indexes():
            return False
        packages = None
        if stdout:
            sys.stdout.write('[+] Updating Package Indexes.\n')
            sys.stdout.flush()
        pacman.refresh_package_indexes()
        if stdout:
            sys.stdout.write('[+] Installing dependencies.\n')
            sys.stdout.flush()
        if pacman.package_manager == 'apt-get':
            packages = ['python3', 'python3-pip', 'nodejs', 'npm']
        elif pacman.package_manager == 'yum':
            pacman.install_packages(['curl', 'gcc-c++', 'make'])
            p = subprocess.Popen('curl --silent --location https://rpm.nodesource.com/setup_10.x | sudo bash -',
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, close_fds=True)
            p.communicate()
            if p.returncode != 0:
                sys.stderr.write('[-] Could not install nodejs source rpm.\n')
                return False
            packages = ['nodejs', 'python36']
            pacman.install_packages(packages)
        if packages:
            pacman.install_packages(packages)
        else:
            sys.stderr.write('[-] A valid package manager could not be found. Currently supports only YUM '
                             'and apt-get.\n')
            return False
        if stdout:
            sys.stdout.write('[+] Installing configurable-http-proxy. This may take some time.\n')
            sys.stdout.flush()
        p = subprocess.Popen('npm install -g configurable-http-proxy', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             shell=True)
        p.communicate()
        if p.returncode != 0:
            sys.stderr.write('[-] Failed to install configurable-http-proxy, ensure npm is installed and in $PATH: {}\n'
                             ''.format(p.stderr.read()))
            return False
        return True

    @staticmethod
    def install_jupyterhub(stdout=False):
        if stdout:
            sys.stdout.write('[+] Installing JupyterHub and ipython[notebook] via pip3.\n')
            sys.stdout.flush()
        p = subprocess.Popen('python3 -m pip install jupyterhub notebook', stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        p.communicate()
        if p.returncode != 0:
            sys.stderr.write('[-] Failed to install Jupyterhub. '
                             'Ensure python3 and pip3 are installed and in $PATH: {}\n'.format(p.stderr.read()))
            return False
        return True

    def setup_jupyterhub(self, jupyter_password='changeme', stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating jupyter user in dynamite group.\n')
            sys.stdout.flush()
        utilities.create_jupyter_user(password=jupyter_password)
        source_config = os.path.join(const.DEFAULT_CONFIGS, 'dynamite_lab', 'jupyterhub_config.py')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p /var/run/dynamite/jupyterhub/', shell=True)
        shutil.copy(source_config, self.install_directory)


JupyterInstaller.install_dependencies(True)
JupyterInstaller.install_jupyterhub(True)
JupyterInstaller().setup_jupyterhub()

