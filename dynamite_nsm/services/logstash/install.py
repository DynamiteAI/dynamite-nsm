import os
import sys
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
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.logstash import config as logstash_config
from dynamite_nsm.services.logstash import profile as logstash_profile
from dynamite_nsm.services.logstash import process as logstash_process
from dynamite_nsm.services.elasticsearch import profile as elastic_profile
from dynamite_nsm.services.logstash.synesis import config as synesis_config
from dynamite_nsm.services.logstash import exceptions as logstash_exceptions
from dynamite_nsm.services.logstash.synesis import install as synesis_install
from dynamite_nsm.services.logstash.elastiflow import config as elastiflow_config
from dynamite_nsm.services.logstash.elastiflow import install as elastiflow_install


class InstallManager:
    """
    Provides a simple interface for installing a new Logstash collector with ElastiFlow pipelines
    """

    def __init__(self, configuration_directory, install_directory, log_directory, host='0.0.0.0',
                 elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme',
                 heap_size_gigs=4, download_logstash_archive=True, stdout=True, verbose=False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/logstash/)
        :param host: The IP address to listen on (E.G "0.0.0.0")
        :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
        :param elasticsearch_port: A port number for the target elasticsearch instance
        :param elasticsearch_password: The password used for authentication across all builtin ES users
        :param heap_size_gigs: The initial/max java heap space to allocate
        :param download_logstash_archive: If True, download the LogStash archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include output from system utilities
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('LOGSTASH', level=log_level, stdout=stdout)

        self.host = host
        if not elasticsearch_host:
            if elastic_profile.ProcessProfiler().is_installed:
                self.elasticsearch_host = 'localhost'
                self.logger.info(
                    "Assuming LogStash will connect to local ElasticSearch instance, "
                    "as ElasticSearch is installed on this host.")
            else:
                self.logger.error("ElasticSearch must either be installed locally, or a remote host must be specified.")
                raise logstash_exceptions.InstallLogstashError(
                    "ElasticSearch must either be installed locally, or a remote host must be specified.")
        else:
            self.elasticsearch_host = elasticsearch_host
        self.elasticsearch_port = elasticsearch_port
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.elasticsearch_password = elasticsearch_password
        self.heap_size_gigs = heap_size_gigs
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose
        utilities.create_dynamite_environment_file()
        if download_logstash_archive:
            try:
                self.download_logstash(stdout=stdout)
            except (general_exceptions.ArchiveExtractionError, general_exceptions.DownloadError):
                self.logger.error("Failed to download LogStash archive.")
                raise logstash_exceptions.InstallLogstashError("Failed to download LogStash archive.")
        try:
            self.extract_logstash()
        except general_exceptions.ArchiveExtractionError:
            self.logger.error("Failed to extract LogStash archive.")
            raise logstash_exceptions.InstallLogstashError("Failed to extract LogStash archive.")

    def _copy_logstash_files_and_directories(self):
        self.logger.info('Copying required LogStash files and directories.')
        config_paths = [
            'config/logstash.yml',
            'config/jvm.options',
            'config/log4j2.properties'
        ]
        install_paths = [
            'Gemfile',
            'Gemfile.lock',
            'bin/',
            'lib/',
            'logstash-core/',
            'logstash-core-plugin-api/',
            'modules/',
            'tools/',
            'vendor/',
            'x-pack/'
        ]
        path = None
        try:
            for path in config_paths:
                self.logger.debug('Copying {} -> {}'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.LOGSTASH_DIRECTORY_NAME, path)),
                    self.configuration_directory))
                try:
                    shutil.copy(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.LOGSTASH_DIRECTORY_NAME, path)),
                                self.configuration_directory)
                except shutil.Error:
                    self.logger.warning('{} already exists at this path.'.format(path))
        except Exception as e:
            self.logger.error(
                "General error while attempting to copy {} to {}.".format(path, self.configuration_directory))
            self.logger.debug(
                "General error while attempting to copy {} to {}; {}".format(path, self.configuration_directory, e))
            raise logstash_exceptions.InstallLogstashError(
                "General error while attempting to copy {} to {}; {}".format(path, self.configuration_directory, e))
        try:
            for path in install_paths:
                src_install_path = os.path.join(const.INSTALL_CACHE, const.LOGSTASH_DIRECTORY_NAME, path)
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
            raise logstash_exceptions.InstallLogstashError(
                "General error while attempting to copy {} to {}; {}".format(path, self.install_directory, e))

    def _create_logstash_directories(self):
        self.logger.info('Creating LogStash installation, configuration, and logging directories.')
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(self.log_directory, exist_ok=True)
            utilities.makedirs(os.path.join(self.install_directory, 'data'), exist_ok=True)
        except Exception as e:
            self.logger.error('Failed to create required directory structure.')
            self.logger.debug('Failed to create required directory structure; {}'.format(e))
            raise logstash_exceptions.InstallLogstashError(
                "Failed to create required directory structure; {}".format(e))

    def _create_logstash_environment_variables(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            with open(env_file) as env_f:
                env_str = env_f.read()
                if 'LS_PATH_CONF' not in env_str:
                    self.logger.info('Updating LogStash default configuration path [{}]'.format(
                        self.configuration_directory))
                    subprocess.call('echo LS_PATH_CONF="{}" >> {}'.format(self.configuration_directory, env_file),
                                    shell=True)
                if 'LS_HOME' not in env_str:
                    self.logger.info('Updating LogStash default home path [{}]'.format(self.install_directory))
                    subprocess.call('echo LS_HOME="{}" >> {}'.format(self.install_directory, env_file), shell=True)
        except IOError:
            self.logger.error("Failed to open {} for reading.".format(env_file))
            raise logstash_exceptions.InstallLogstashError(
                "Failed to open {} for reading.".format(env_file))
        except Exception as e:
            self.logger.error("General error while creating environment variables in {}.".format(env_file))
            self.logger.debug("General error while creating environment variables in {}; {}".format(env_file, e))
            raise logstash_exceptions.InstallLogstashError(
                "General error while creating environment variables in {}; {}".format(env_file, e))

    def _install_logstash_plugins(self):
        self.logger.info("Installing required LogStash plugins.")
        try:
            if self.verbose:
                subprocess.call('{}/bin/logstash-plugin install logstash-codec-sflow'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict())
                subprocess.call('{}/bin/logstash-plugin install logstash-codec-netflow'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict())
                subprocess.call('{}/bin/logstash-plugin install logstash-filter-dns'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict())

                subprocess.call('{}/bin/logstash-plugin install logstash-filter-geoip'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict())
                subprocess.call(
                    '{}/bin/logstash-plugin install logstash-filter-translate'.format(self.install_directory),
                    shell=True, env=utilities.get_environment_file_dict())
                subprocess.call('{}/bin/logstash-plugin install logstash-input-beats'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict())
            else:
                subprocess.call('{}/bin/logstash-plugin install logstash-codec-sflow'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.call('{}/bin/logstash-plugin install logstash-codec-netflow'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.call('{}/bin/logstash-plugin install logstash-filter-dns'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.call('{}/bin/logstash-plugin install logstash-filter-geoip'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.call(
                    '{}/bin/logstash-plugin install logstash-filter-translate'.format(self.install_directory),
                    shell=True, env=utilities.get_environment_file_dict(),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.call('{}/bin/logstash-plugin install logstash-input-beats'.format(self.install_directory),
                                shell=True, env=utilities.get_environment_file_dict(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            self.logger.error('General error while attempting to install logstash plugins')
            self.logger.debug("General error while attempting to install logstash plugins; {}".format(e))
            raise logstash_exceptions.InstallLogstashError(
                "General error while attempting to install logstash plugins; {}".format(e))

    def _setup_default_logstash_configs(self):
        self.logger.info('Overwriting default configuration')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'logstash.yml'),
                    self.configuration_directory)
        ls_config = logstash_config.ConfigManager(configuration_directory=self.configuration_directory)
        self.logger.info('Setting up JVM default heap settings [{}GB]'.format(self.heap_size_gigs))
        ls_config.java_initial_memory = int(self.heap_size_gigs)
        ls_config.java_maximum_memory = int(self.heap_size_gigs)
        ls_config.write_configs()

    def _setup_elastiflow(self):
        self.logger.info("Setting up ElastiFlow [Dynamite Patched Version].")
        try:
            ef_install = elastiflow_install.InstallManager(install_directory=os.path.join(
                self.configuration_directory, 'elastiflow')
            )
            ef_install.setup_logstash_elastiflow()
        except Exception as e:
            self.logger.error("General error occurred while installing ElastiFlow.")
            self.logger.debug("General error occurred while installing ElastiFlow; {}".format(e))
            raise logstash_exceptions.InstallLogstashError(
                "General error occurred while installing Elastiflow; {}".format(e))
        try:
            ef_config = elastiflow_config.ConfigManager()
            ef_config.ipfix_tcp_ipv4_host = self.host
            ef_config.netflow_ipv4_host = self.host
            ef_config.sflow_ipv4_host = self.host
            ef_config.zeek_ipv4_host = self.host
            ef_config.es_host = self.elasticsearch_host + ':' + str(self.elasticsearch_port)
            ef_config.es_passwd = self.elasticsearch_password
        except general_exceptions.ReadConfigError:
            self.logger.error('Error while reading ElastiFlow environmental variables.')
            raise logstash_exceptions.InstallLogstashError("Error while reading ElastiFlow environmental variables.")
        try:
            ef_config.write_environment_variables()
        except general_exceptions.WriteConfigError:
            self.logger.error('Error while writing ElastiFlow environmental variables.')
            raise logstash_exceptions.InstallLogstashError("Error while writing ElastiFlow environmental variables.")

    def _setup_synesis(self):
        try:
            self.logger.info("Setting up Synesis [Dynamite Patched Version].")
            syn_install = synesis_install.InstallManager(
                install_directory=os.path.join(self.configuration_directory, 'synesis'))
            syn_install.setup_logstash_synesis()
        except Exception as e:
            self.logger.error("General error occurred while installing Synesis.")
            self.logger.debug("General error occurred while installing Synesis; {}".format(e))
            raise logstash_exceptions.InstallLogstashError(
                "General error occurred while installing Synesis; {}".format(e))
        try:
            syn_config = synesis_config.ConfigManager()
            syn_config.suricata_es_host = self.elasticsearch_host + ':' + str(self.elasticsearch_port)
            syn_config.suricata_resolve_ip2host = True
            syn_config.es_passwd = self.elasticsearch_password
        except general_exceptions.ReadConfigError:
            self.logger.error('Error while reading Synesis environmental variables.')
            raise logstash_exceptions.InstallLogstashError("Error while reading Synesis environmental variables.")
        try:
            syn_config.write_environment_variables()
        except general_exceptions.WriteConfigError:
            self.logger.error('Error while writing Synesis environmental variables.')
            raise logstash_exceptions.InstallLogstashError("Error while writing Synesis environmental variables.")

    def _update_sysctl(self):
        self.logger.info('Setting up Max File Handles [65535] VM Max Map Count [262144]')
        try:
            utilities.update_user_file_handle_limits()
        except Exception as e:
            self.logger.error('General error while setting user file-handle limits.')
            self.logger.debug("General error while setting user file-handle limits; {}".format(e))
            raise logstash_exceptions.InstallLogstashError(
                "General error while setting user file-handle limits; {}".format(e))
        try:
            utilities.update_sysctl(verbose=self.verbose)
        except Exception as e:
            self.logger.error('General error while setting VM Max Map Count.')
            self.logger.debug("General error while setting VM Max Map Count; {}".format(e))
            raise logstash_exceptions.InstallLogstashError(
                "General error while setting VM Max Map Count; {}".format(e))

    @staticmethod
    def download_logstash(stdout=False):
        """
        Download Logstash archive

        :param stdout: Print output to console
        """
        url = None
        try:
            with open(const.LOGSTASH_MIRRORS, 'r') as ls_archive:
                for url in ls_archive.readlines():
                    if utilities.download_file(url, const.LOGSTASH_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading logstash from {}; {}".format(url, e))

    @staticmethod
    def extract_logstash():
        """
        Extract Logstash to local install_cache
        """

        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.LOGSTASH_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract logstash archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract logstash archive; {}".format(e))

    def setup_logstash(self):
        """
        Create required directories, files, and variables to run LogStash successfully;
        """

        self._create_logstash_directories()
        self._copy_logstash_files_and_directories()
        self._create_logstash_environment_variables()
        self._setup_default_logstash_configs()
        self._update_sysctl()
        self._setup_elastiflow()
        self._setup_synesis()
        self._install_logstash_plugins()

        try:
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'pipelines.yml'),
                        os.path.join(self.configuration_directory, 'pipelines.yml'))
        except Exception as e:
            raise logstash_exceptions.InstallLogstashError(
                "General error while copying pipeline.yml file; {}".format(e))
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(self.log_directory, exist_ok=True)
        except Exception as e:
            raise logstash_exceptions.InstallLogstashError(
                "General error occurred while attempting to create root directories; {}".format(e))
        try:
            utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
            utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
            utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')
        except Exception as e:
            self.logger.error(
                "General error occurred while attempting to set permissions on root directories.")
            self.logger.debug(
                "General error occurred while attempting to set permissions on root directories; {}".format(e))
            raise logstash_exceptions.InstallLogstashError(
                "General error occurred while attempting to set permissions on root directories; {}".format(e))


def install_logstash(configuration_directory, install_directory, log_directory, host='0.0.0.0',
                     elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme',
                     heap_size_gigs=4, install_jdk=True, create_dynamite_user=True, stdout=False, verbose=False):
    """
    Install Logstash with ElastiFlow & Synesis

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
    :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/logstash/)
    :param host: The IP address to bind LogStash listeners too
    :param elasticsearch_password: The password used for authentication across all builtin ES users
    :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
    :param elasticsearch_port: A port number for the target elasticsearch instance
    :param elasticsearch_password: The password used for authentication across all builtin ES users
    :param heap_size_gigs: The initial/max java heap space to allocate
    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run Logstash/ElasticSearch
    :param stdout: Print the output to console
    :param verbose: Include output from system utilities
    :return: True, if installation succeeded
    """
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('LOGSTASH', level=log_level, stdout=stdout)

    ls_profiler = logstash_profile.ProcessProfiler()
    if ls_profiler.is_installed:
        logger.error('LogStash is already installed.')
        raise logstash_exceptions.AlreadyInstalledLogstashError()
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('\n\033[93m[-] WARNING! LogStash should have at-least 6GB to run '
                         'currently available [{} GB]\033[0m\n'.format(
            utilities.get_memory_available_bytes() / (1000 ** 3)))
        if str(utilities.prompt_input('\033[93m[?] Continue? [y|N]:\033[0m ')).lower() != 'y':
            sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    ls_installer = InstallManager(configuration_directory, install_directory, log_directory, host=host,
                                  elasticsearch_host=elasticsearch_host, elasticsearch_port=elasticsearch_port,
                                  elasticsearch_password=elasticsearch_password, heap_size_gigs=heap_size_gigs,
                                  download_logstash_archive=not ls_profiler.is_downloaded, stdout=stdout,
                                  verbose=verbose
                                  )
    if install_jdk:
        try:
            utilities.download_java(stdout=stdout)
            utilities.extract_java()
            utilities.setup_java()
        except Exception as e:
            logger.error('General error occurred while attempting to setup Java.')
            logger.debug("General error occurred while attempting to setup Java; {}".format(e))
            raise logstash_exceptions.InstallLogstashError(
                "General error occurred while attempting to setup Java; {}".format(e))
    if create_dynamite_user:
        utilities.create_dynamite_user(utilities.generate_random_password(50))
    ls_installer.setup_logstash()


def uninstall_logstash(prompt_user=True, stdout=True, verbose=False):
    """
    Install Logstash with ElastiFlow & Synesis

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('LOGSTASH', level=log_level, stdout=stdout)

    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('LS_PATH_CONF')
    ls_profiler = logstash_profile.ProcessProfiler()
    ls_config = logstash_config.ConfigManager(configuration_directory=configuration_directory)
    if not ls_profiler.is_installed:
        logger.error('LogStash is not installed.')
        raise logstash_exceptions.UninstallLogstashError("LogStash is not installed.")
    if prompt_user:
        sys.stderr.write(
            '\n\033[93m[-] WARNING! Removing Logstash Will Prevent ElasticSearch From Receiving Events.\033[0m\n')
        resp = utilities.prompt_input('\n\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    if ls_profiler.is_running:
        logstash_process.ProcessManager().stop()
    try:
        shutil.rmtree(ls_config.ls_path_conf)
        shutil.rmtree(ls_config.ls_home)
        shutil.rmtree(ls_config.path_logs)
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        with open(env_file) as env_fr:
            for line in env_fr.readlines():
                if 'LS_PATH_CONF' in line:
                    continue
                elif 'LS_HOME' in line:
                    continue
                elif 'ELASTIFLOW_' in line:
                    continue
                elif 'SYNLITE_' in line:
                    continue
                elif 'ES_PASSWD' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'
            with open(env_file, 'w') as env_fw:
                env_fw.write(env_lines)
    except Exception as e:
        logger.error("General error occurred while attempting to uninstall LogStash.".format(e))
        logger.debug("General error occurred while attempting to uninstall LogStash; {}".format(e))
        raise logstash_exceptions.UninstallLogstashError(
            "General error occurred while attempting to uninstall LogStash; {}".format(e))
