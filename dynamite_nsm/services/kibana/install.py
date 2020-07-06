import os
import sys
import time
import shutil
import logging
import tarfile
import subprocess

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.kibana import config as kibana_configs
from dynamite_nsm.services.kibana import process as kibana_process
from dynamite_nsm.services.kibana import profile as kibana_profile
from dynamite_nsm.services.kibana import exceptions as kibana_exceptions
from dynamite_nsm.services.elasticsearch import process as elastic_process
from dynamite_nsm.services.elasticsearch import profile as elastic_profile


class InstallManager:
    """
    Provides a simple interface for installing a new Kibana interface with ElastiFlow/Synesis dashboards
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
        :param verbose: Include detailed debug messages
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('KIBANA', level=log_level, stdout=stdout)

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
        utilities.create_dynamite_environment_file()
        if download_kibana_archive:
            try:
                self.download_kibana(stdout=stdout)
            except (general_exceptions.ArchiveExtractionError, general_exceptions.DownloadError):
                self.logger.error("Failed to download Kibana archive.")
                raise kibana_exceptions.InstallKibanaError("Failed to download Kibana archive.")
        try:
            self.extract_kibana()
        except general_exceptions.ArchiveExtractionError:
            self.logger.error("Failed to extract Kibana archive.")
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
                self.logger.debug('Copying {} -> {}'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                    self.configuration_directory))
                try:
                    shutil.copy(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                                self.configuration_directory)
                except shutil.Error:
                    self.logger.warning('{} already exists at this path.'.format(path))
            for path in install_paths:
                src_install_path = os.path.join(const.INSTALL_CACHE, const.KIBANA_DIRECTORY_NAME, path)
                dst_install_path = os.path.join(self.install_directory, path)
                self.logger.debug('Copying {} -> {}'.format(src_install_path, dst_install_path))
                try:
                    if os.path.isdir(src_install_path):
                        shutil.copytree(src_install_path, dst_install_path)
                    else:
                        shutil.copy(src_install_path, dst_install_path)
                except shutil.Error:
                    self.logger.warning('{} already exists at this path.'.format(path))
        except Exception as e:
            self.logger.error(
                "General error while attempting to copy {} to {}.".format(path, self.install_directory))
            self.logger.debug(
                "General error while attempting to copy {} to {}; {}".format(path, self.install_directory, e))
            raise kibana_exceptions.InstallKibanaError(
                "General error while attempting to copy {} to {}; {}".format(path, self.install_directory, e))

    def _create_kibana_directories(self):
        self.logger.info('Creating Kibana installation, configuration, and logging directories.')
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(self.log_directory, exist_ok=True)
            utilities.makedirs(os.path.join(self.install_directory, 'data'), exist_ok=True)
        except Exception as e:
            self.logger.error('Failed to create required directory structure.')
            self.logger.debug('Failed to create required directory structure; {}'.format(e))
            raise kibana_exceptions.InstallKibanaError(
                "Failed to create required directory structure; {}".format(e))

    def _create_kibana_environment_variables(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            if 'KIBANA_PATH_CONF' not in open(env_file).read():
                self.logger.info('Updating Kibana default configuration path [{}]'.format(
                    self.configuration_directory))
                subprocess.call('echo KIBANA_PATH_CONF="{}" >> {}'.format(
                    self.configuration_directory, env_file),
                    shell=True)
            if 'KIBANA_HOME' not in open(env_file).read():
                self.logger.info('Updating Kibana default home path [{}]'.format(self.install_directory))
                subprocess.call('echo KIBANA_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                shell=True)
            if 'KIBANA_LOGS' not in open(env_file).read():
                self.logger.info('Updating Kibana default log path [{}]'.format(self.log_directory))
                subprocess.call('echo KIBANA_LOGS="{}" >> {}'.format(self.log_directory, env_file),
                                shell=True)
        except IOError:
            raise kibana_exceptions.InstallKibanaError("Failed to open {} for reading.".format(env_file))
        except Exception as e:
            raise kibana_exceptions.InstallKibanaError(
                "General error while creating environment variables in {}; {}".format(env_file, e))

    def _install_kibana_objects(self):
        self.logger.info('Installing Kibana Dashboards')
        self.logger.info('Waiting for ElasticSearch to become accessible.')
        # Start ElasticSearch if it is installed locally and is not running
        if self.elasticsearch_host in ['localhost', '127.0.0.1', '0.0.0.0', '::1', '::/128']:
            self.logger.info('Starting ElasticSearch.')
            elastic_process.ProcessManager().start()
            while not elastic_profile.ProcessProfiler().is_listening:
                self.logger.info('Waiting for ElasticSearch API to become accessible.')
                time.sleep(5)
            self.logger.info('ElasticSearch API is up.')
            self.logger.info('Sleeping for 5 seconds, while ElasticSearch API finishes booting.')
            time.sleep(5)
        try:
            kibana_proc = kibana_process.ProcessManager()
            kibana_proc.optimize()
            utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
            utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
            time.sleep(5)
            self.logger.info('Starting Kibana.')
            kibana_proc.start()
        except Exception as e:
            raise kibana_exceptions.InstallKibanaError("General error while starting Kibana process; {}".format(e))
        kibana_api_start_attempts = 0
        while not kibana_profile.ProcessProfiler().is_listening and kibana_api_start_attempts != 5:
            self.logger.info('Waiting for Kibana API to become accessible.')
            kibana_api_start_attempts += 1
            time.sleep(5)
        if kibana_api_start_attempts == 5:
            self.logger.error('Kibana API could not be started after {} attempts.'.format(kibana_api_start_attempts))
            raise kibana_exceptions.InstallKibanaError(
                "Kibana API could not be started after {} attempts.".format(kibana_api_start_attempts))
        self.logger.info('Kibana API is up.')
        self.logger.info('Sleeping for 10 seconds, while Kibana API finishes booting.')
        time.sleep(10)
        api_config = kibana_configs.ApiConfigManager(self.configuration_directory)
        kibana_object_create_attempts = 1
        while kibana_object_create_attempts != 5:
            try:
                self.logger.info('[Attempt {}] Attempting to install dashboards/visualizations.'.format(
                    kibana_object_create_attempts))
                api_config.create_dynamite_kibana_objects()
                break
            except kibana_exceptions.CreateKibanaObjectsError:
                kibana_object_create_attempts += 1
                time.sleep(10)
        if kibana_object_create_attempts == 5:
            self.logger.error(
                "Kibana objects could not be created after {} attempts".format(kibana_object_create_attempts))
            raise kibana_exceptions.InstallKibanaError(
                "Kibana objects could not be created after {} attempts".format(kibana_object_create_attempts))
        self.logger.info('Successfully created dashboards/visualizations.')
        kibana_proc.stop()

    def _setup_default_kibana_configs(self):
        self.logger.info('Overwriting default configuration.')
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
            self.logger.error('Failed to write kibana config.')
            raise kibana_exceptions.InstallKibanaError("Failed to write kibana config.")
        except Exception as e:
            self.logger.error('General error occurred while writing kibana configs.')
            self.logger.debug('General error occurred while writing kibana configs; {}'.format(e))
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
    def extract_kibana():
        """
        Extract Kibana to local install_cache
        """
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.KIBANA_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
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
            pacman = package_manager.OSPackageManager(stdout=self.stdout, verbose=self.verbose)
        except general_exceptions.InvalidOsPackageManagerDetectedError:
            self.logger.error("No valid OS package manager detected.")
            raise kibana_exceptions.InstallKibanaError("No valid OS package manager detected.")
        try:
            pacman.refresh_package_indexes()
            pacman.install_packages(['curl'])
        except (general_exceptions.OsPackageManagerInstallError, general_exceptions.OsPackageManagerRefreshError):
            self.logger.error("Failed to install one or more packages; {}".format(["curl"]))
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
            self.logger.error("General error occurred while attempting to set permissions on root directories.")
            self.logger.debug(
                "General error occurred while attempting to set permissions on root directories; {}".format(e))
            raise kibana_exceptions.InstallKibanaError(
                "General error occurred while attempting to set permissions on root directories; {}".format(e))


def install_kibana(install_directory, configuration_directory, log_directory, host='0.0.0.0', port=5601,
                   elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme',
                   create_dynamite_user=True, stdout=False, verbose=False):
    """
    Install Kibana/ElastiFlow/Synesis Dashboards

    :param install_directory: Path to the install directory (E.G /opt/dynamite/kibana/)
    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/kibana/)
    :param host: The IP address to listen on (E.G "0.0.0.0")
    :param port: The port that the Kibana UI/API is bound to (E.G 5601)
    :param elasticsearch_host: A hostname/IP of the target ElasticSearch instance
    :param elasticsearch_port: A port number for the target ElasticSearch instance
    :param elasticsearch_password: The password used for authentication across all builtin ES users
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run
    Logstash/ElasticSearch/Kibana
    :param stdout: Print the output to console
    :param verbose: Include output from system utilities
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('KIBANA', level=log_level, stdout=stdout)

    kb_profiler = kibana_profile.ProcessProfiler()
    if kb_profiler.is_installed:
        logger.error('Kibana is already installed. If you wish to re-install, first uninstall.')
        raise kibana_exceptions.AlreadyInstalledKibanaError()
    if utilities.get_memory_available_bytes() < 2 * (1000 ** 3):
        sys.stderr.write('\n\033[93m[-] WARNING! Kibana should have at-least 2GB to run '
                         'currently available [{} GB]\033[0m\n'.format(
            utilities.get_memory_available_bytes() / (1000 ** 3)))
        if str(utilities.prompt_input('\033[93m[?] Continue? [y|N]:\033[0m ')).lower() != 'y':
            sys.stdout.write('\n[+] Exiting\n')
            exit(0)
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


def uninstall_kibana(prompt_user=True, stdout=True, verbose=False):
    """
    Uninstall Kibana/ElastiFlow/Synesis Dashboards

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('KIBANA', level=log_level, stdout=stdout)

    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    kb_profiler = kibana_profile.ProcessProfiler()
    if not kb_profiler.is_installed:
        raise kibana_exceptions.UninstallKibanaError("Kibana is not installed.")
    configuration_directory = environment_variables.get('KIBANA_PATH_CONF')
    kb_config = kibana_configs.ConfigManager(configuration_directory)
    if prompt_user:
        sys.stderr.write(
            '\n\033[93m[-] WARNING! Removing Kibana will uninstall all visualizations and saved searches previously '
            'created.\033[0m\n')
        resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\n\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    if kb_profiler.is_running:
        kibana_process.ProcessManager().stop()
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
    except Exception as e:
        logger.error("General error occurred while attempting to uninstall Kibana.".format(e))
        logger.debug("General error occurred while attempting to uninstall Kibana; {}".format(e))
        raise kibana_exceptions.UninstallKibanaError(
            "General error occurred while attempting to uninstall kibana; {}".format(e))
