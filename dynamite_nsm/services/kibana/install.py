import os
import sys
import time
import shutil
import tarfile
import traceback
import subprocess

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.services.kibana import config as kibana_configs
from dynamite_nsm.services.kibana import process as kibana_process
from dynamite_nsm.services.kibana import profile as kibana_profile
from dynamite_nsm.services.elasticsearch import process as elastic_process
from dynamite_nsm.services.elasticsearch import profile as elastic_profile


class InstallManager:
    """
    Provides a simple interface for installing a new Kibana interface with ElastiFlow dashboards
    """

    def __init__(self, install_directory, configuration_directory, log_directory, host='0.0.0.0', port=5601,
                 elasticsearch_host=None, elasticsearch_port=None, elasticsearch_password='changeme',
                 download_kibana_archive=True, stdout=True, verbose=False):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/kibana/)
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/kibana/)
        :param host: The IP address to listen on (E.G "0.0.0.0")
        :param port: The port that the Kibana UI/API is bound to (E.G 5601)
        :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
        :param elasticsearch_port: A port number for the target elasticsearch instance
        :param elasticsearch_password: The password used for authentication across all builtin ES users
        :param download_kibana_archive: If True, download the Kibana archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """
        self.host = host
        self.port = port
        self.elasticsearch_host = elasticsearch_host
        self.elasticsearch_port = elasticsearch_port
        self.elasticsearch_password = elasticsearch_password
        if not elasticsearch_host:
            if elastic_profile.ProcessProfiler().is_installed:
                self.elasticsearch_host = 'localhost'
            else:
                raise Exception("ElasticSearch must either be installed locally, or a remote host must be specified.")
        self.install_directory = install_directory
        self.configuration_directory = configuration_directory
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose
        if download_kibana_archive:
            self.download_kibana()
            self.extract_kibana()

    def _create_kibana_directories(self):
        if self.stdout:
            sys.stdout.write('[+] Creating kibana install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.install_directory, 'data')), shell=True)

    def _copy_kibana_files_and_directories(self):
        config_paths = [
            'config/kibana.yml',
        ]
        install_paths = [
            'package.json',
            'bin/',
            'built_assets/',
            'node/',
            'node_modules/',
            'optimize/',
            'plugins/',
            'src/',
            'target/',
            'webpackShims/'
        ]
        for path in config_paths:
            if self.stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                    self.configuration_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                            self.configuration_directory)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            if self.stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                    self.install_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                            self.install_directory)
            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))

    def _create_kibana_environment_variables(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if 'KIBANA_PATH_CONF' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating Kibana default configuration path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo KIBANA_PATH_CONF="{}" >> {}'.format(
                self.configuration_directory, env_file),
                shell=True)
        if 'KIBANA_HOME' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating Kibana default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo KIBANA_HOME="{}" >> {}'.format(self.install_directory, env_file),
                            shell=True)
        if 'KIBANA_LOGS' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating Kibana default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo KIBANA_LOGS="{}" >> {}'.format(self.log_directory, env_file),
                            shell=True)

    def _install_kibana_objects(self):
        elastic_installed_locally = elastic_profile.ProcessProfiler().is_installed or \
                                    self.elasticsearch_host != 'localhost'
        if kibana_profile.ProcessProfiler().is_installed and elastic_installed_locally:
            if self.stdout:
                sys.stdout.write('[+] Installing Kibana Dashboards\n')
            if self.stdout:
                sys.stdout.write('[+] Waiting for ElasticSearch to become accessible.\n')
            # Start ElasticSearch if it is installed locally and is not running
            if self.elasticsearch_host in ['localhost', '127.0.0.1', '0.0.0.0', '::1', '::/128']:
                sys.stdout.write('[+] Starting ElasticSearch.\n')
                elastic_process.ProcessManager().start(stdout=self.stdout)
                sys.stdout.flush()
                while not elastic_profile.ProcessProfiler().is_listening:
                    if self.stdout:
                        sys.stdout.write('[+] Waiting for ElasticSearch API to become accessible.\n')
                    time.sleep(5)
                if self.stdout:
                    sys.stdout.write('[+] ElasticSearch API is up.\n')
                    sys.stdout.write('[+] Sleeping for 10 seconds, while ElasticSearch API finishes booting.\n')
                    sys.stdout.flush()
                time.sleep(10)
            kibana_proc = kibana_process.ProcessManager()
            kibana_proc.optimize(stdout=self.stdout)
            utilities.set_ownership_of_file(const.BIN_PATH, user='dynamite', group='dynamite')
            utilities.set_ownership_of_file(const.CONFIG_PATH, user='dynamite', group='dynamite')
            time.sleep(5)
            sys.stdout.write('[+] Starting Kibana.\n')
            kibana_proc.start(stdout=self.stdout)
            while not kibana_profile.ProcessProfiler().is_listening:
                if self.stdout:
                    sys.stdout.write('[+] Waiting for Kibana API to become accessible.\n')
                time.sleep(5)
            if self.stdout:
                sys.stdout.write('[+] Kibana API is up.\n')
                sys.stdout.write('[+] Sleeping for 15 seconds, while Kibana API finishes booting.\n')
                sys.stdout.flush()
            time.sleep(15)
            api_config = kibana_configs.ApiConfigManager(self.configuration_directory)
            kibana_object_create_attempts = 1
            while not api_config.create_dynamite_kibana_objects():
                if self.stdout:
                    sys.stdout.write('[+] Attempting to dashboards/visualizations [Attempt {}]\n'.format(
                        kibana_object_create_attempts))
                kibana_object_create_attempts += 1
                time.sleep(10)
            if self.stdout:
                sys.stdout.write('[+] Successfully created dashboards/visualizations.\n')
            kibana_proc.stop()

    def _setup_default_kibana_configs(self):
        if self.stdout:
            sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'kibana', 'kibana.yml'),
                    self.configuration_directory)
        local_config = kibana_configs.ConfigManager(self.configuration_directory)
        local_config.elasticsearch_hosts = ['http://{}:{}'.format(self.elasticsearch_host,
                                                                  self.elasticsearch_port)]
        local_config.server_host = self.host
        local_config.server_port = self.port
        local_config.elasticsearch_password = self.elasticsearch_password
        local_config.elasticsearch_username = 'elastic'
        local_config.write_config()

    @staticmethod
    def download_kibana(stdout=False):
        """
        Download Kibana archive

        :param stdout: Print output to console
        """
        for url in open(const.KIBANA_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.KIBANA_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_kibana(stdout=False):
        """
        Extract Kibana to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.KIBANA_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.KIBANA_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_kibana(self):
        """
        Create required directories, files, and variables to run ElasticSearch successfully;
        """
        pacman = package_manager.OSPackageManager(verbose=self.verbose)
        pacman.refresh_package_indexes()
        pacman.install_packages(['curl'])
        self._create_kibana_directories()
        self._copy_kibana_files_and_directories()
        self._create_kibana_environment_variables()
        self._setup_default_kibana_configs()
        self._install_kibana_objects()
        utilities.set_ownership_of_file(const.CONFIG_PATH, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(const.BIN_PATH, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file('/var/log/dynamite', user='dynamite', group='dynamite')


def install_kibana(install_directory, configuration_directory, log_directory, elasticsearch_host='localhost',
                   elasticsearch_port=9200, elasticsearch_password='changeme',
                   install_jdk=True, create_dynamite_user=True, stdout=False, verbose=False):
    """
    Install Kibana/ElastiFlow Dashboards
    :param install_directory: Path to the install directory (E.G /opt/dynamite/kibana/)
    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/kibana/)
    :param elasticsearch_host: [Optional] A hostname/IP of the target elasticsearch instance
    :param elasticsearch_port: [Optional] A port number for the target elasticsearch instance
    :param elasticsearch_password: The password used for authentication across all builtin ES users
    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run
    Logstash/ElasticSearch/Kibana
    :param stdout: Print the output to console
    :param verbose: Include output from system utilities
    :return: True, if installation succeeded
    """
    kb_profiler = kibana_profile.ProcessProfiler()
    if kb_profiler.is_installed:
        sys.stderr.write('[-] Kibana is already installed. If you wish to re-install, first uninstall.\n')
        return False
    if utilities.get_memory_available_bytes() < 2 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite Kibana requires at-least 2GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes() / (1000 ** 3)
        ))
        return False
    try:
        kb_installer = InstallManager(install_directory, configuration_directory, log_directory,
                                      elasticsearch_host=elasticsearch_host,
                                      elasticsearch_port=elasticsearch_port,
                                      elasticsearch_password=elasticsearch_password,
                                      download_kibana_archive=not kb_profiler.is_downloaded, stdout=stdout,
                                      verbose=verbose)
        if install_jdk:
            utilities.download_java(stdout=stdout)
            utilities.extract_java(stdout=stdout)
            utilities.setup_java()
        if create_dynamite_user:
            utilities.create_dynamite_user(utilities.generate_random_password(50))
        kb_installer.setup_kibana()
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install Kibana: ')
        traceback.print_exc(file=sys.stderr)
        return False
    if stdout:
        sys.stdout.write('[+] *** Kibana + Dashboards installed successfully. ***\n\n')
        sys.stdout.write('[+] Next, Start your collector: \'dynamite start kibana\'.\n')
        sys.stdout.flush()
    return kibana_profile.ProcessProfiler(stderr=False).is_installed


def uninstall_kibana(configuration_directory, stdout=False, prompt_user=True):
    """
    Uninstall Kibana/ElastiFlow Dashboards

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    :return: True, if uninstall succeeded
    """
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    kb_profiler = kibana_profile.ProcessProfiler()
    kb_config = kibana_configs.ConfigManager(configuration_directory)
    if not kb_profiler.is_installed:
        sys.stderr.write('[-] Kibana is not installed.\n')
        return False
    if prompt_user:
        sys.stderr.write('[-] WARNING! REMOVING KIBANA WILL PREVENT YOU FROM VIEWING NETWORK EVENTS.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    if kb_profiler.is_running:
        kibana_process.ProcessManager().stop(stdout=stdout)
    try:
        shutil.rmtree(kb_config.kibana_path_conf)
        shutil.rmtree(kb_config.kibana_home)
        shutil.rmtree(kb_config.kibana_logs)
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        for line in open(env_file).readlines():
            if 'KIBANA_PATH_CONF' in line:
                continue
            elif 'KIBANA_HOME' in line:
                continue
            elif 'KIBANA_LOGS' in line:
                continue
            elif line.strip() == '':
                continue
            env_lines += line.strip() + '\n'
        open(env_file, 'w').write(env_lines)
        if stdout:
            sys.stdout.write('[+] Kibana uninstalled successfully.\n')
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to uninstall Kibana: ')
        traceback.print_exc(file=sys.stderr)
        return False
    return True
