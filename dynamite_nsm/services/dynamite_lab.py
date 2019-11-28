import os
import sys
import time
import json
import shutil
import signal
import tarfile
import subprocess
from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.services.elasticsearch import ElasticProfiler

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

CONFIGURATION_DIRECTORY = '/etc/dynamite/dynamite_sdk/'
NOTEBOOK_HOME = '/home/jupyter/lab/'


class DynamiteLabConfigurator:
    """
    Wrapper for configuring dynamite-sdk-lite config.cfg
    """

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
    """
    Provides a simple interface for installing a new Installing the DynamiteLab environment
        - Jupyterhub
        - dynamite-sdk-lite
    """
    def __init__(self,
                 elasticsearch_host=None,
                 elasticsearch_port=None,
                 elasticsearch_password='changeme',
                 jupyterhub_password='changeme',
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 notebook_home=NOTEBOOK_HOME,
                 stdout=False):

        self.elasticsearch_host = elasticsearch_host
        self.elasticsearch_port = elasticsearch_port
        self.elasticsearch_password = elasticsearch_password
        self.jupyterhub_password = jupyterhub_password
        self.configuration_directory = configuration_directory
        self.notebook_home = notebook_home
        self.download_dynamite_sdk(stdout=stdout)
        self.extract_dynamite_sdk(stdout=stdout)
        self.install_jupyterhub_dependencies(stdout=stdout)
        self.install_jupyterhub(stdout=stdout)
        self.stdout = stdout

        if not elasticsearch_host:
            if ElasticProfiler().is_installed:
                self.elasticsearch_host = 'localhost'
            else:
                raise Exception("Elasticsearch must either be installed locally, or a remote host must be specified.")

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
        """
        Installs Jupyterhub and ipython[notebook]

        :param stdout: Print the output to console
        :return: True, if installation succeeded
        """
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
        """
        Sets up sdk files; and installs globally
        """
        if self.stdout:
            sys.stdout.write('[+] Copying DynamiteSDK into lab environment.\n')
            sys.stdout.flush()
        subprocess.call('mkdir -p {}'.format(self.notebook_home), shell=True)
        sdk_install_cache = os.path.join(const.INSTALL_CACHE, const.DYNAMITE_SDK_DIRECTORY_NAME)
        utilities.copytree(os.path.join(sdk_install_cache, 'notebooks'), self.notebook_home)
        shutil.copy(os.path.join(sdk_install_cache, 'dynamite_sdk', 'config.cfg.example'),
                           os.path.join(self.configuration_directory, 'config.cfg'))
        utilities.set_ownership_of_file(self.notebook_home, user='jupyter', group='dynamite')
        p = subprocess.Popen(['python3', 'setup.py', 'install'], cwd=sdk_install_cache)
        p.communicate()
        dynamite_sdk_config = DynamiteLabConfigurator(configuration_directory=self.configuration_directory)
        dynamite_sdk_config.elasticsearch_url = 'http://{}:{}'.format(self.elasticsearch_host, self.elasticsearch_port)
        dynamite_sdk_config.elasticsearch_user = 'elastic'
        dynamite_sdk_config.elasticsearch_password = self.elasticsearch_password
        dynamite_sdk_config.write_config()

    def setup_jupyterhub(self):
        """
        Sets up jupyterhub configuration; and creates required user for initial login
        """
        if self.stdout:
            sys.stdout.write('[+] Creating jupyter user in dynamite group.\n')
            sys.stdout.flush()
        utilities.create_jupyter_user(password=self.jupyterhub_password)
        if self.stdout:
            sys.stdout.write('[+] Creating lab directories and files.\n')
            sys.stdout.flush()
        source_config = os.path.join(const.DEFAULT_CONFIGS, 'dynamite_lab', 'jupyterhub_config.py')
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        if 'DYNAMITE_LAB_CONFIG' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating Dynamite Lab Config path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo DYNAMITE_LAB_CONFIG="{}" >> /etc/dynamite/environment'.format(
                self.configuration_directory), shell=True)
        shutil.copy(source_config, self.configuration_directory)
        os.symlink('/usr/local/bin/jupyter*', '/usr/bin/')


class DynamiteLabProfiler:
    """
    Interface for determining whether JupyterHub is installed/configured/running properly.
    """
    def __init__(self, stderr=False):
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_configured = self._is_configured(stderr=stderr)
        self.is_running = self._is_running()

    def __str__(self):
        return json.dumps({
            'INSTALLED': self.is_installed,
            'CONFIGURED': self.is_configured,
            'RUNNING': self.is_running,
        }, indent=1)

    @staticmethod
    def _is_installed(stderr=False):
        try:
            p = subprocess.Popen('jupyterhub --version')
            p.communicate()
            return p.returncode == 0
        except OSError:
            if stderr:
                sys.stderr.write('[-] Could not locate JupyterHub in $PATH.')
            return False

    @staticmethod
    def _is_configured(stderr=False):
        try:
            env_dict = utilities.get_environment_file_dict()
        except IOError:
            if stderr:
                sys.stderr.write('[-] DynamiteLab environment variables haven\'t been created.\n')
            return False
        dynamite_lab_config = env_dict.get('DYNAMITE_LAB_CONFIG')
        if not dynamite_lab_config:
            if stderr:
                sys.stderr.write('[-] DynamiteLab configuration directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(dynamite_lab_config):
            if stderr:
                sys.stderr.write('[-] DynamiteLab configuration directory could not be located at {}.\n'.format(
                    dynamite_lab_config))
            return False
        try:
            DynamiteLabConfigurator(configuration_directory=dynamite_lab_config)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable config.cfg \n')
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return JupyterHubProcess().status()['RUNNING']
        except Exception:
            return False

    def get_profile(self):
        return {
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }


class JupyterHubProcess:
    """
    An interface for start|stop|status|restart of the JupyterHub process
    """
    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('DYNAMITE_LAB_CONFIG')
        try:
            self.pid = int(open('/var/run/dynamite/jupyterhub/jupyterhub.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the JupyterHub process
        :param stdout: Print output to console
        :return: True, if started successfully
        """

        if not os.path.exists('/var/run/dynamite/jupyterhub/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/jupyterhub/'), shell=True)

        if not utilities.check_pid(self.pid):
            subprocess.call('jupyterhub -f {}'.format(self.configuration_directory), shell=True)
        else:
            sys.stderr.write('[-] JupyterHub is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting JupyterHub on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/jupyterhub/jupyterhub.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting JupyterHub on PID [{}]\n'.format(retry + 1, self.pid)
                if stdout:
                    sys.stdout.write(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(5)
                else:
                    return True
            except IOError:
                if stdout:
                    sys.stdout.write(start_message)
                retry += 1
                time.sleep(3)
        return False

    def stop(self, stdout=False):
        """
        Stop the ElasticSearch process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop JupyterHub [{}]\n'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGKILL
                else:
                    # Kill the zombie after the third attempt of asking it to kill itself
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)

                alive = utilities.check_pid(self.pid)
            except Exception as e:
                sys.stderr.write('[-] An error occurred while attempting to stop JupyterHub: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the JupyterHub process

        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

    def status(self):
        """
        Check the status of the JupyterHub process

        :return: A dictionary containing the run status and relevant configuration options
        """

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'USER': 'root'
        }


def install_dynamite_lab(
    elasticsearch_host='localhost',
    elasticsearch_port=9200,
    elasticsearch_password='changeme',
    jupyterhub_password='changeme',
    stdout=True):

    dynamite_lab_installer = DynamiteLabInstaller(elasticsearch_host, elasticsearch_port, elasticsearch_password,
                                                  jupyterhub_password, stdout=stdout)
    dynamite_lab_installer.setup_dynamite_sdk()
    dynamite_lab_installer.setup_jupyterhub()

'''

def uninstall_dynamite_lab(stdout=False, prompt_user=True):
    """
    Uninstall ElasticSearch

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    :return: True, if uninstall succeeded
    """
    es_profiler = ElasticProfiler()
    es_config = ElasticConfigurator(configuration_directory=CONFIGURATION_DIRECTORY)
    if not es_profiler.is_installed:
        sys.stderr.write('[-] ElasticSearch is not installed.\n')
        return False
    if prompt_user:
        sys.stderr.write('[-] WARNING! REMOVING ELASTICSEARCH WILL LIKELY RESULT IN ALL DATA BEING LOST.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    if es_profiler.is_running:
        ElasticProcess().stop(stdout=stdout)
    try:
        shutil.rmtree(es_config.configuration_directory)
        shutil.rmtree(es_config.es_home)
        shutil.rmtree(es_config.get_log_path())
        shutil.rmtree('/tmp/dynamite/install_cache/', ignore_errors=True)
        env_lines = ''
        for line in open('/etc/dynamite/environment').readlines():
            if 'ES_PATH_CONF' in line:
                continue
            elif 'ES_HOME' in line:
                continue
            elif line.strip() == '':
                continue
            env_lines += line.strip() + '\n'
        open('/etc/dynamite/environment', 'w').write(env_lines)
        if stdout:
            sys.stdout.write('[+] ElasticSearch uninstalled successfully.\n')
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to uninstall ElasticSearch: ')
        traceback.print_exc(file=sys.stderr)
        return False
    return True
'''

install_dynamite_lab('localhost', stdout=True)
print(DynamiteLabProfiler().get_profile())
JupyterHubProcess().start(stdout=True)