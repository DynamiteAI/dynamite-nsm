import sys
import subprocess
from dynamite_nsm import package_manager
INSTALL_DIRECTORY = '/opt/dynamite/jupyterhub/'


class JupyterInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        pass

    @staticmethod
    def install_dependencies(stdout=True):
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
    def install_jupyterhub(stdout=True):
        if stdout:
            sys.stdout.write('Installing JupyterHub and ipython[notebook] via pip3.\n')
            sys.stdout.flush()
        p = subprocess.Popen('python3 -m pip install jupyterhub notebook', stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        p.communicate()
        if p.returncode != 0:
            sys.stderr.write('[-] Failed to install Jupyterhub. '
                             'Ensure python3 and pip3 are installed and in $PATH: {}\n'.format(p.stderr.read()))
            return False
        return True


if JupyterInstaller.install_dependencies():
    print(JupyterInstaller.install_jupyterhub())
