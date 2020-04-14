import os
import sys
import time
import shutil
import tarfile
import subprocess

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.kibana import config as kibana_configs
from dynamite_nsm.services.kibana import process as kibana_process
from dynamite_nsm.services.kibana import profile as kibana_profile
from dynamite_nsm.services.kibana import exceptions as kibana_exceptions
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
                raise kibana_exceptions.InstallKibanaError(
                    "ElasticSearch must either be installed locally, or a remote host must be specified.")
        self.install_directory = install_directory
        self.configuration_directory = configuration_directory
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose
        if download_kibana_archive:
            try:
                self.download_kibana(stdout=stdout)
            except (general_exceptions.ArchiveExtractionError, general_exceptions.DownloadError):
                raise kibana_exceptions.InstallKibanaError("Failed to download Kibana archive.")
        try:
            self.extract_kibana(stdout=stdout)
        except general_exceptions.ArchiveExtractionError:
            raise kibana_exceptions.InstallKibanaError("Failed to extract Kibana archive.")

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
        path = None
        try:
            for path in config_paths:
                if self.stdout:
                    sys.stdout.write('[+] Copying {} -> {}\n'.format(
                        os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                        self.configuration_directory))
                try:
                    shutil.copy(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                                self.configuration_directory)
                except shutil.Error as e:
                    sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
            for path in install_paths:
                src_install_path = os.path.join(const.INSTALL_CACHE, const.KIBANA_DIRECTORY_NAME, path)
                dst_install_path = os.path.join(self.install_directory, path)
                if self.stdout:
                    sys.stdout.write('[+] Copying {} -> {}\n'.format(src_install_path, dst_install_path))
                try:
                    if os.path.isdir(src_install_path):
                        shutil.copytree(src_install_path, dst_install_path)
                    else:
                        shutil.copy(src_install_path, dst_install_path)
                except shutil.Error as e:
                    sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        except Exception as e:
            raise kibana_exceptions.InstallKibanaError(
                "General error while attempting to copy {} to {}; {}".format(path, self.install_directory, e))

    def _create_kibana_directories(self):
        if self.stdout:
            sys.stdout.write('[+] Creating kibana install|configuration|logging directories.\n')
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(self.log_directory, exist_ok=True)
            utilities.makedirs(os.path.join(self.install_directory, 'data'), exist_ok=True)
        except Exception as e:
            raise kibana_exceptions.InstallKibanaError(
                "Failed to create required directory structure; {}".format(e))

    def _create_kibana_environment_variables(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        try:
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
        except IOError:
            raise kibana_exceptions.InstallKibanaError("Failed to open {} for reading.".format(env_file))
        except Exception as e:
            raise kibana_exceptions.InstallKibanaError(
                "General error while creating environment variables in {}; {}".format(env_file, e))

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
            try:
                kibana_proc = kibana_process.ProcessManager()
                kibana_proc.optimize(stdout=self.stdout)
                utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
                utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
                time.sleep(5)
                sys.stdout.write('[+] Starting Kibana.\n')
                kibana_proc.start(stdout=self.stdout)
            except Exception as e:
                raise kibana_exceptions.InstallKibanaError("General error while starting Kibana process; {}".format(e))
            kibana_api_start_attempts = 0
            while not kibana_profile.ProcessProfiler().is_listening and kibana_api_start_attempts != 5:
                if self.stdout:
                    sys.stdout.write('[+] Waiting for Kibana API to become accessible.\n')
                kibana_api_start_attempts += 1
                time.sleep(5)
            if kibana_api_start_attempts == 5:
                raise kibana_exceptions.InstallKibanaError(
                    "Kibana API could not be started after {} attempts.".format(kibana_api_start_attempts))
            if self.stdout:
                sys.stdout.write('[+] Kibana API is up.\n')
                sys.stdout.write('[+] Sleeping for 10 seconds, while Kibana API finishes booting.\n')
                sys.stdout.flush()
            time.sleep(10)
            api_config = kibana_configs.ApiConfigManager(self.configuration_directory)
            kibana_object_create_attempts = 0
            while kibana_object_create_attempts != 5:
                try:
                    api_config.create_dynamite_kibana_objects()
                except kibana_exceptions.CreateKibanaObjectsError:
                    if self.stdout:
                        sys.stdout.write('[+] Attempting to dashboards/visualizations [Attempt {}]\n'.format(
                            kibana_object_create_attempts))
                    kibana_object_create_attempts += 1
                    time.sleep(10)
            if kibana_object_create_attempts == 5:
                raise kibana_exceptions.InstallKibanaError(
                    "Kibana objects could not be created after {} attempts".format(kibana_object_create_attempts))
            if self.stdout:
                sys.stdout.write('[+] Successfully created dashboards/visualizations.\n')
            kibana_proc.stop()

    def _setup_default_kibana_configs(self):
        if self.stdout:
            sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'kibana', 'kibana.yml'),
                    self.configuration_directory)
        try:
            local_config = kibana_configs.ConfigManager(self.configuration_directory)
        except kibana_exceptions.ReadKibanaConfigError:
            raise kibana_exceptions.InstallKibanaError("Failed to read kibana config.")
        except Exception as e:
            raise kibana_exceptions.InstallKibanaError(
                "General error occurred while reading kibana configs; {}".format(e))
        local_config.elasticsearch_hosts = ['http://{}:{}'.format(self.elasticsearch_host,
                                                                  self.elasticsearch_port)]
        local_config.server_host = self.host
        local_config.server_port = self.port
        local_config.elasticsearch_password = self.elasticsearch_password
        local_config.elasticsearch_username = 'elastic'
        try:
            local_config.write_config()
        except kibana_exceptions.WriteKibanaConfigError:
            raise kibana_exceptions.InstallKibanaError("Failed to write kibana config.")
        except Exception as e:
            raise kibana_exceptions.InstallKibanaError(
                "General error occurred while writing kibana configs; {}".format(e))

    @staticmethod
    def download_kibana(stdout=False):
        """
        Download Kibana archive

        :param stdout: Print output to console
        """
        url = None
        try:
            with open(const.KIBANA_MIRRORS, 'r') as kb_archive:
                for url in kb_archive.readlines():
                    if utilities.download_file(url, const.KIBANA_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading kibana from {}; {}".format(url, e))

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
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract kibana archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract kibana archive; {}".format(e))

    def setup_kibana(self):
        """
        Create required directories, files, and variables to run ElasticSearch successfully;
        """
        try:
            pacman = package_manager.OSPackageManager(verbose=self.verbose)
        except general_exceptions.InvalidOsPackageManagerDetectedError:
            raise kibana_exceptions.InstallKibanaError("No valid OS package manager detected.")
        try:
            pacman.refresh_package_indexes()
            pacman.install_packages(['curl'])
        except (general_exceptions.OsPackageManagerInstallError, general_exceptions.OsPackageManagerRefreshError):
            raise kibana_exceptions.InstallKibanaError("Failed to install one or more packages; {}".format(["curl"]))
        self._create_kibana_directories()
        self._copy_kibana_files_and_directories()
        self._create_kibana_environment_variables()
        self._setup_default_kibana_configs()
        self._install_kibana_objects()
        try:
            utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
            utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
            utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')
        except Exception as e:
            raise kibana_exceptions.InstallKibanaError(
                "General error occurred while attempting to set permissions on root directories; {}".format(e))


def install_kibana(install_directory, configuration_directory, log_directory, host='0.0.0.0', port=5601,
                   elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme',
                   create_dynamite_user=True, stdout=False, verbose=False):
    """
    Install Kibana/ElastiFlow Dashboards
    :param install_directory: Path to the install directory (E.G /opt/dynamite/kibana/)
    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/kibana/)
    :param host: The IP address to listen on (E.G "0.0.0.0")
    :param port: The port that the Kibana UI/API is bound to (E.G 5601)
    :param elasticsearch_host: [Optional] A hostname/IP of the target elasticsearch instance
    :param elasticsearch_port: [Optional] A port number for the target elasticsearch instance
    :param elasticsearch_password: The password used for authentication across all builtin ES users
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run
    Logstash/ElasticSearch/Kibana
    :param stdout: Print the output to console
    :param verbose: Include output from system utilities
    """

    kb_profiler = kibana_profile.ProcessProfiler()
    if kb_profiler.is_installed:
        sys.stderr.write('[-] Kibana is already installed. If you wish to re-install, first uninstall.\n')
        raise kibana_exceptions.InstallKibanaError(
            "Kibana is already installed. If you wish to re-install, first uninstall.")
    if utilities.get_memory_available_bytes() < 2 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite Kibana requires at-least 2GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes() / (1000 ** 3)
        ))
        raise kibana_exceptions.InstallKibanaError(
            "Dynamite Kibana requires at-least 2GB to run currently available [{} GB]")
    kb_installer = InstallManager(install_directory, configuration_directory, log_directory,
                                  host=host,
                                  port=port,
                                  elasticsearch_host=elasticsearch_host,
                                  elasticsearch_port=elasticsearch_port,
                                  elasticsearch_password=elasticsearch_password,
                                  download_kibana_archive=not kb_profiler.is_downloaded, stdout=stdout,
                                  verbose=verbose)
    if create_dynamite_user:
        utilities.create_dynamite_user(utilities.generate_random_password(50))
    kb_installer.setup_kibana()


def uninstall_kibana(stdout=False, prompt_user=True):
    """
    Uninstall Kibana/ElastiFlow Dashboards

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    """
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    kb_profiler = kibana_profile.ProcessProfiler()
    if not kb_profiler.is_installed:
        raise kibana_exceptions.UninstallKibanaError("Kibana is not installed.")
    configuration_directory = environment_variables.get('KIBANA_PATH_CONF')
    kb_config = kibana_configs.ConfigManager(configuration_directory)
    if prompt_user:
        sys.stderr.write(
            '[-] WARNING! Removing Kibana will uninstall all visualizations and saved searches previously created.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return
    if kb_profiler.is_running:
        kibana_process.ProcessManager().stop(stdout=stdout)
    try:
        shutil.rmtree(kb_config.kibana_path_conf)
        shutil.rmtree(kb_config.kibana_home)
        shutil.rmtree(kb_config.kibana_logs)
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        with open(env_file) as env_fr:
            for line in env_fr.readlines():
                if 'KIBANA_PATH_CONF' in line:
                    continue
                elif 'KIBANA_HOME' in line:
                    continue
                elif 'KIBANA_LOGS' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'
        with open(env_file, 'w') as env_fw:
            env_fw.write(env_lines)
        if stdout:
            sys.stdout.write('[+] Kibana uninstalled successfully.\n')
    except Exception as e:
        raise kibana_exceptions.UninstallKibanaError(
            "General error occurred while attempting to uninstall kibana; {}".format(e))
