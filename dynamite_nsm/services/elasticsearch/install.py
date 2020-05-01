import os
import sys
import time
import shutil
import logging
import tarfile
import subprocess

try:
    from urllib2 import urlopen
    from urllib2 import URLError
    from urllib2 import HTTPError
    from urllib2 import Request
except Exception:
    from urllib.request import urlopen
    from urllib.error import URLError
    from urllib.error import HTTPError
    from urllib.request import Request
    from urllib.parse import urlencode

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.elasticsearch import config as elastic_configs
from dynamite_nsm.services.elasticsearch import process as elastic_process
from dynamite_nsm.services.elasticsearch import profile as elastic_profile
from dynamite_nsm.services.elasticsearch import exceptions as elastic_exceptions


class InstallManager:
    """
    Provides a simple interface for installing an ElasticSearch node
    """

    def __init__(self, configuration_directory, install_directory, log_directory, host='0.0.0.0', port=9200,
                 password='changeme', heap_size_gigs=4, download_elasticsearch_archive=True, stdout=False,
                 verbose=False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/elasticsearch/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/elasticsearch/)
        :param host: The IP address to listen on (E.G "0.0.0.0")
        :param port: The port that the ES API is bound to (E.G 9200)
        :param password: The password used for authentication across all builtin users
        :param heap_size_gigs: The initial/max java heap space to allocate
        :param download_elasticsearch_archive: If True, download the ElasticSearch archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('ELASTICSEARCH', level=log_level, stdout=stdout)

        self.host = host
        self.port = port
        self.password = password
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.heap_size_gigs = heap_size_gigs
        self.stdout = stdout
        self.verbose = verbose
        utilities.create_dynamite_environment_file()
        if download_elasticsearch_archive:
            try:
                self.download_elasticsearch(stdout=stdout)
            except (general_exceptions.ArchiveExtractionError, general_exceptions.DownloadError):
                self.logger.error("Failed to download ElasticSearch archive.")
                raise elastic_exceptions.InstallElasticsearchError("Failed to download ElasticSearch archive.")
        try:
            self.extract_elasticsearch()
        except general_exceptions.ArchiveExtractionError:
            self.logger.error("Failed to extract ElasticSearch archive.")
            raise elastic_exceptions.InstallElasticsearchError("Failed to extract ElasticSearch archive.")

    def _copy_elasticsearch_files_and_directories(self):
        config_paths = [
            'config/elasticsearch.yml',
            'config/jvm.options',
            'config/log4j2.properties'
        ]
        install_paths = [
            'bin/',
            'lib/',
            'logs/',
            'modules/',
            'plugins/'
        ]
        path = None
        try:
            for path in config_paths:
                self.logger.debug('Copying {} -> {}'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                    self.configuration_directory))
                try:
                    shutil.copy(
                        os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                        self.configuration_directory)
                except shutil.Error:
                    self.logger.warning('{} already exists at this path.'.format(path))
        except Exception as e:
            self.logger.error(
                "General error while attempting to copy {} to {}.".format(path, self.configuration_directory))
            self.logger.debug(
                "General error while attempting to copy {} to {}; {}".format(path, self.configuration_directory, e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while attempting to copy {} to {}; {}".format(path, self.configuration_directory, e))
        try:
            for path in install_paths:
                src_install_path = os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_DIRECTORY_NAME, path)
                dst_install_path = os.path.join(self.install_directory, path)
                self.logger.debug('Copying {} -> {}'.format(src_install_path, dst_install_path))
                try:
                    utilities.makedirs(dst_install_path, exist_ok=True)
                    utilities.copytree(src_install_path, dst_install_path)
                except shutil.Error:
                    self.logger.warning('{} already exists at this path.'.format(path))
        except Exception as e:
            self.logger.error(
                "General error while attempting to copy {} to {}.".format(path, self.install_directory))
            self.logger.debug(
                "General error while attempting to copy {} to {}; {}".format(path, self.install_directory, e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while attempting to copy {} to {}; {}".format(path, self.install_directory, e))

    def _create_elasticsearch_directories(self):
        self.logger.info('Creating ElasticSearch installation, configuration, and logging directories.')
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(self.log_directory, exist_ok=True)
            utilities.makedirs(os.path.join(self.install_directory, 'data'), exist_ok=True)
        except Exception as e:
            self.logger.error('Failed to create required directory structure.')
            self.logger.debug('Failed to create required directory structure; {}'.format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "Failed to create required directory structure; {}".format(e))

    def _create_elasticsearch_environment_variables(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            with open(env_file) as env_f:
                env_str = env_f.read()
                if 'ES_PATH_CONF' not in env_str:
                    self.logger.info('Updating ElasticSearch default configuration path [{}]'.format(
                        self.configuration_directory))
                    subprocess.call('echo ES_PATH_CONF="{}" >> {}'.format(self.configuration_directory, env_file),
                                    shell=True)
                if 'ES_HOME' not in env_str:
                    self.logger.info('Updating ElasticSearch default home path [{}]'.format(self.install_directory))
                    subprocess.call('echo ES_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
        except IOError:
            self.logger.error("Failed to open {} for reading.".format(env_file))
            raise elastic_exceptions.InstallElasticsearchError("Failed to open {} for reading.".format(env_file))
        except Exception as e:
            self.logger.error("General error while creating environment variables in {}.".format(env_file))
            self.logger.debug("General error while creating environment variables in {}; {}".format(env_file, e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while creating environment variables in {}; {}".format(env_file, e))

    def _setup_default_elasticsearch_configs(self):
        self.logger.info('Overwriting default configuration.')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'elasticsearch', 'elasticsearch.yml'),
                    self.configuration_directory)
        try:
            es_config = elastic_configs.ConfigManager(configuration_directory=self.configuration_directory)
        except elastic_exceptions.ReadElasticConfigError:
            self.logger.error('Failed to read ElasticSearch config.')
            raise elastic_exceptions.InstallElasticsearchError("Failed to read ElasticSearch config.")
        except Exception as e:
            self.logger.error("General error occurred while reading ElasticSearch configs.")
            self.logger.debug("General error occurred while reading ElasticSearch configs; {}".format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while reading elasticsearch configs; {}".format(e))
        self.logger.info('Setting up JVM default heap settings [{}GB]'.format(self.heap_size_gigs))
        es_config.java_initial_memory = int(self.heap_size_gigs)
        es_config.java_maximum_memory = int(self.heap_size_gigs)
        es_config.network_host = self.host
        es_config.http_port = self.port
        try:
            es_config.write_configs()
        except elastic_exceptions.WriteElasticConfigError:
            self.logger.error('Failed to write ElasticSearch config.')
            raise elastic_exceptions.InstallElasticsearchError("Failed to write ElasticSearch config.")
        except Exception as e:
            self.logger.error("General error occurred while writing ElasticSearch configs.")
            self.logger.debug("General error occurred while writing ElasticSearch configs; {}".format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while writing ElasticSearch configs; {}".format(e))

    def _update_sysctl(self):
        self.logger.info('Setting up Max File Handles [65535] VM Max Map Count [262144]')
        try:
            utilities.update_user_file_handle_limits()
        except Exception as e:
            self.logger.error('General error while setting user file-handle limits.')
            self.logger.debug("General error while setting user file-handle limits; {}".format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while setting user file-handle limits; {}".format(e))
        try:
            utilities.update_sysctl(verbose=self.verbose)
        except Exception as e:
            self.logger.error('General error while setting VM Max Map Count.')
            self.logger.debug("General error while setting VM Max Map Count; {}".format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while setting VM Max Map Count; {}".format(e))

    @staticmethod
    def download_elasticsearch(stdout=False):
        """
        Download ElasticSearch archive

        :param stdout: Print output to console
        """

        url = None
        try:
            with open(const.ELASTICSEARCH_MIRRORS, 'r') as es_archive:
                for url in es_archive.readlines():
                    if utilities.download_file(url, const.ELASTICSEARCH_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading elasticsearch from {}; {}".format(url, e))

    @staticmethod
    def extract_elasticsearch():
        """
        Extract ElasticSearch to local install_cache
        """
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract elasticsearch archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract elasticsearch archive; {}".format(e))

    def setup_elasticsearch(self):
        """
        Create required directories, files, and variables to run ElasticSearch successfully;
        Setup Java environment
        """
        self._create_elasticsearch_directories()
        self._copy_elasticsearch_files_and_directories()
        self._create_elasticsearch_environment_variables()
        self._setup_default_elasticsearch_configs()
        self._update_sysctl()
        try:
            utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
            utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
            utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')
        except Exception as e:
            self.logger.error("General error occurred while attempting to set permissions on root directories.")
            self.logger.debug(
                "General error occurred while attempting to set permissions on root directories; {}".format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to set permissions on root directories; {}".format(e))
        self.setup_passwords()

    def setup_passwords(self):
        env_dict = utilities.get_environment_file_dict()

        def setup_from_bootstrap(s):
            bootstrap_users_and_passwords = {}
            for line in s.split('\n'):
                if 'PASSWORD' in line:
                    _, user, _, password = line.split(' ')
                    if not isinstance(password, str):
                        password = password.decode()
                    bootstrap_users_and_passwords[user] = password
            es_pass_config = elastic_configs.PasswordConfigManager(
                auth_user='elastic',
                current_password=bootstrap_users_and_passwords['elastic'],
                stdout=self.stdout,
                verbose=self.verbose
            )
            es_pass_config.set_all_passwords(new_password=self.password)

        if not elastic_profile.ProcessProfiler().is_installed:
            self.logger.error('ElasticSearch must be installed and running to bootstrap passwords.')
            raise elastic_exceptions.InstallElasticsearchError(
                "ElasticSearch must be installed and running to bootstrap passwords.")
        self.logger.info('Creating certificate keystore.')
        es_config_path = os.path.join(self.configuration_directory, 'config')
        try:
            utilities.makedirs(es_config_path, exist_ok=True)
        except Exception as e:
            self.logger.error("General error occurred while attempting to create {} directory.".format(es_config_path))
            self.logger.debug(
                "General error occurred while attempting to create {} directory; {}".format(es_config_path, e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to create {} directory; {}".format(es_config_path, e))
        es_cert_util = os.path.join(self.install_directory, 'bin', 'elasticsearch-certutil')
        es_cert_keystore = os.path.join(self.configuration_directory, 'config', 'elastic-certificates.p12')
        cert_p = subprocess.Popen([es_cert_util, 'cert', '-out', es_cert_keystore, '-pass', ''],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE,
                                  env=env_dict)
        try:
            cert_p_res = cert_p.communicate()
        except Exception as e:
            self.logger.error("General error occurred while attempting to install SSL keystores.")
            self.logger.debug("General error occurred while attempting to install SSL keystores; {}".format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to install SSL keystores; {}".format(e))
        if not os.path.exists(es_cert_keystore):
            self.logger.error('Failed to setup SSL certificate keystore: \noutput: {}\n\t'.format(cert_p_res))
            raise elastic_exceptions.InstallElasticsearchError("Failed to setup SSL keystore; {}".format(cert_p_res))
        keystore_config_path = os.path.join(self.configuration_directory, 'config')
        try:
            utilities.set_ownership_of_file(keystore_config_path, user='dynamite', group='dynamite')
        except Exception as e:
            self.logger.error(
                'General error occurred while attempting to set permissions for {}.'.format(keystore_config_path))
            self.logger.debug(
                "General error occurred while attempting to set permissions for {}; {}".format(keystore_config_path, e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to set permissions for {}; {}".format(keystore_config_path, e)
            )
        if not elastic_profile.ProcessProfiler().is_running:
            elastic_process.ProcessManager().start()
            attempts = 0
            while not elastic_profile.ProcessProfiler().is_listening:
                self.logger.info('Waiting for ElasticSearch API to become accessible.')
                time.sleep(5)
                attempts += 1
                if attempts == 10:
                    self.logger.error("Failed to start ElasticSearch API after 10 attempts.")
                    raise elastic_exceptions.InstallElasticsearchError(
                        "Failed to start Elasticsearch API after 10 attempts.")
            self.logger.info('ElasticSearch API is up.')
            self.logger.debug('Sleeping for 5 seconds, while ElasticSearch API finishes booting.')
            time.sleep(5)
        self.logger.info('Bootstrapping passwords.')
        es_password_util = os.path.join(self.install_directory, 'bin', 'elasticsearch-setup-passwords')
        bootstrap_p = subprocess.Popen([es_password_util, 'auto'],
                                       cwd=self.configuration_directory, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, stdin=subprocess.PIPE, env=env_dict)
        try:
            bootstrap_p_res = bootstrap_p.communicate(input=b'y\n')
            if not bootstrap_p_res:
                self.logger.error('Failed to setup new passwords.')
                raise elastic_exceptions.InstallElasticsearchError("Failed to bootstrap password.")
            try:
                if not isinstance(bootstrap_p_res[0], str):
                    setup_from_bootstrap(bootstrap_p_res[0].decode())
                else:
                    setup_from_bootstrap(bootstrap_p_res[0])
            except general_exceptions.ResetPasswordError:
                self.logger.error("Failed to bootstrap password.")
                raise elastic_exceptions.InstallElasticsearchError("Failed to bootstrap password.")
        except Exception as e:
            self.logger.error("General error occurred while attempting to bootstrap ElasticSearch passwords.")
            self.logger.debug(
                "General error occurred while attempting to bootstrap ElasticSearch passwords {}".format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to bootstrap ElasticSearch passwords {}".format(e))


def install_elasticsearch(configuration_directory, install_directory, log_directory, password='changeme',
                          heap_size_gigs=4, install_jdk=True, create_dynamite_user=True, stdout=True, verbose=False):
    """
    Install ElasticSearch

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
    :param install_directory: Path to the install directory (E.G /opt/dynamite/elasticsearch/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/elasticsearch/)
    :param password: The password used for authentication across all builtin users
    :param heap_size_gigs: The initial/max java heap space to allocate
    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run Logstash/ElasticSearch
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('ELASTICSEARCH', level=log_level, stdout=stdout)

    es_profiler = elastic_profile.ProcessProfiler()
    if es_profiler.is_installed:
        logger.error('ElasticSearch is already installed.')
        raise elastic_exceptions.AlreadyInstalledElasticsearchError()
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('\n\033[93m[-] WARNING! ElasticSearch should have at-least 6GB to run '
                         'currently available [{} GB]\033[0m\n'.format(
            utilities.get_memory_available_bytes() / (1000 ** 3)))
        if str(utilities.prompt_input('\033[93m[?] Continue? [y|N]:\033[0m ')).lower() != 'y':
            sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    es_installer = InstallManager(configuration_directory=configuration_directory,
                                  install_directory=install_directory, log_directory=log_directory,
                                  password=password, heap_size_gigs=heap_size_gigs,
                                  download_elasticsearch_archive=not es_profiler.is_downloaded,
                                  stdout=stdout, verbose=verbose)
    if install_jdk:
        try:
            utilities.download_java(stdout=stdout)
            utilities.extract_java()
            utilities.setup_java()
        except Exception as e:
            logger.error('General error occurred while attempting to setup Java.')
            logger.debug("General error occurred while attempting to setup Java; {}".format(e))
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to setup Java; {}".format(e))
    if create_dynamite_user:
        utilities.create_dynamite_user(utilities.generate_random_password(50))
    es_installer.setup_elasticsearch()


def uninstall_elasticsearch(prompt_user=True, stdout=True, verbose=False):
    """
    Uninstall ElasticSearch

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('ELASTICSEARCH', level=log_level, stdout=stdout)

    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    es_profiler = elastic_profile.ProcessProfiler()
    if not es_profiler.is_installed:
        logger.error('ElasticSearch is not installed.')
        raise elastic_exceptions.UninstallElasticsearchError("ElasticSearch is not installed.")
    configuration_directory = environment_variables.get('ES_PATH_CONF')
    es_config = elastic_configs.ConfigManager(configuration_directory=configuration_directory)
    if prompt_user:
        sys.stderr.write(
            '\n\033[93m[-] WARNING! Removing ElasticSearch Will Delete All Data.'
            '\033[0m\n')
        resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\n\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    if es_profiler.is_running:
        elastic_process.ProcessManager().stop()
    try:
        shutil.rmtree(es_config.configuration_directory)
        shutil.rmtree(es_config.es_home)
        shutil.rmtree(es_config.path_logs)
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        with open(env_file) as env_fr:
            for line in env_fr.readlines():
                if 'ES_PATH_CONF' in line:
                    continue
                elif 'ES_HOME' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'
        with open(env_file, 'w') as env_fw:
            env_fw.write(env_lines)
    except Exception as e:
        logger.error("General error occurred while attempting to uninstall ElasticSearch.".format(e))
        logger.debug("General error occurred while attempting to uninstall ElasticSearch; {}".format(e))
        raise elastic_exceptions.UninstallElasticsearchError(
            "General error occurred while attempting to uninstall ElasticSearch; {}".format(e))
