import os
import sys
import shutil
import tarfile
import subprocess
from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

CONFIGURATION_DIRECTORY = '/etc/dynamite/dynamite_sdk/'
NOTEBOOK_HOME = '/home/jupyter/lab/'


class DynamiteLabConfigurator:

    tokens = {
        'elasticsearch_url': 'AUTHENTICATION',
        'elasticsearch_user': 'AUTHENTICATION',
        'elasticsearch_password': 'AUTHENTICATION',
        'timeout': 'SEARCH',
        'max_results': 'SEARCH'
    }

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        self.configuration_directory = configuration_directory
        self.elasticsearch_url = None
        self.elasticsearch_user = None
        self.elasticsearch_password = None
        self.timeout = None
        self.max_results = None
        self.config = self._parse_lab_config()

    def _parse_lab_config(self):
        """
        :return: A dictionary representing the configurations storred within node.cfg
        """
        config_parser = ConfigParser()
        config_parser.readfp(open(os.path.join(self.configuration_directory, 'config.cfg')))
        for section in config_parser.sections():
            for item in config_parser.items(section):
                key, value = item
                setattr(self, key, value)
        return config_parser

    def write_config(self):
        for k, v in vars(self).items():
            if k not in self.tokens.keys():
                continue
            section = self.tokens[k]
            self.config.set(section, k, v)
        with open(os.path.join(self.configuration_directory, 'config.cfg'), 'w') as configfile:
            self.config.write(configfile)


class DynamiteLabInstaller:

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY, notebook_home=NOTEBOOK_HOME, stdout=False):
        self.configuration_directory = configuration_directory
        self.notebook_home = notebook_home
        self.download_dynamite_sdk(stdout=stdout)
        self.extract_dynamite_sdk(stdout=stdout)
        self.install_jupyterhub_dependencies(stdout=stdout)
        self.install_jupyterhub(stdout=stdout)
        self.stdout = stdout

    @staticmethod
    def download_dynamite_sdk(stdout=False):
        """
        Download DynamiteSDK archive

        :param stdout: Print output to console
        """
        for url in open(const.DYNAMITE_SDK_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.DYNAMITE_SDK_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_dynamite_sdk(stdout=False):
        """
        Extract DynamiteSDK to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.DYNAMITE_SDK_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.DYNAMITE_SDK_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    @staticmethod
    def install_jupyterhub_dependencies(stdout=False):
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

    def setup_dynamite_sdk(self):
        if self.stdout:
            sys.stdout.write('[+] Copying DynamiteSDK into lab environment.\n')
            sys.stdout.flush()
        subprocess.call('mkdir -p {}'.format(self.notebook_home), shell=True)
        sdk_install_cache = os.path.join(const.INSTALL_CACHE, const.DYNAMITE_SDK_DIRECTORY_NAME)
        utilities.copytree(os.path.join(sdk_install_cache, 'notebooks'), self.notebook_home)
        shutil.copy2(os.path.join(sdk_install_cache, 'dynamite_sdk', 'config.cfg.example'),
                           self.configuration_directory)
        utilities.set_ownership_of_file(self.notebook_home, user='jupyter', group='dynamite')
        p = subprocess.Popen(['python3', 'setup.py', 'install'], cwd=sdk_install_cache)
        p.communicate()
        dynamite_sdk_config = DynamiteLabConfigurator(configuration_directory=self.configuration_directory)
        dynamite_sdk_config.elasticsearch_host = 'test'
        dynamite_sdk_config.write_config()

    def setup_jupyterhub(self, jupyter_password='changeme'):
        if self.stdout:
            sys.stdout.write('[+] Creating jupyter user in dynamite group.\n')
            sys.stdout.flush()
        utilities.create_jupyter_user(password=jupyter_password)
        if self.stdout:
            sys.stdout.write('[+] Creating lab directories and files.\n')
            sys.stdout.flush()
        source_config = os.path.join(const.DEFAULT_CONFIGS, 'dynamite_lab', 'jupyterhub_config.py')
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        # subprocess.call('mkdir -p /var/run/dynamite/jupyterhub/', shell=True)
        shutil.copy(source_config, self.configuration_directory)


installer = DynamiteLabInstaller(stdout=True)
installer.setup_jupyterhub()
installer.setup_dynamite_sdk()