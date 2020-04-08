import os
import sys
import time
import shutil
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
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.elasticsearch import config as elastic_configs
from dynamite_nsm.services.elasticsearch import process as elastic_process
from dynamite_nsm.services.elasticsearch import profile as elastic_profile
from dynamite_nsm.services.elasticsearch import exceptions as elastic_exceptions


class InstallManager:
    """
    Provides a simple interface for installing a new ElasticSearch node
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
        :param verbose: Include output from system utilities
        """

        self.host = host
        self.port = port
        self.password = password
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.heap_size_gigs = heap_size_gigs
        self.stdout = stdout
        self.verbose = verbose
        if download_elasticsearch_archive:
            try:
                self.download_elasticsearch(stdout=stdout)
                self.extract_elasticsearch(stdout=stdout)
            except (general_exceptions.ArchiveExtractionError, general_exceptions.DownloadError):
                raise elastic_exceptions.InstallElasticsearchError("Failed to download/extract Elasticsearch archive.")

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
                if self.stdout:
                    sys.stdout.write('[+] Copying {} -> {}\n'.format(
                        os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                        self.configuration_directory))
                try:
                    shutil.copy(
                        os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                        self.configuration_directory)
                except shutil.Error as e:
                    sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while attempting to copy {} to {}; {}".format(path, self.configuration_directory, e))
        try:
            for path in install_paths:
                src_install_path = os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_DIRECTORY_NAME, path)
                dst_install_path = os.path.join(self.install_directory, path)
                if self.stdout:
                    sys.stdout.write('[+] Copying {} -> {}\n'.format(src_install_path, dst_install_path))
                try:
                    utilities.makedirs(dst_install_path, exist_ok=True)
                    utilities.copytree(src_install_path, dst_install_path)
                except shutil.Error as e:
                    sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while attempting to copy {} to {}; {}".format(path, self.install_directory, e))

    def _create_elasticsearch_directories(self):
        if self.stdout:
            sys.stdout.write('[+] Creating elasticsearch install|configuration|logging directories.\n')
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(self.log_directory, exist_ok=True)
            utilities.makedirs(os.path.join(self.install_directory, 'data'), exist_ok=True)
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "Failed to create required directory structure; {}".format(e))

    def _create_elasticsearch_environment_variables(self, stdout=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            with open(env_file) as env_f:
                env_str = env_f.read()
                if 'ES_PATH_CONF' not in env_str:
                    if stdout:
                        sys.stdout.write('[+] Updating ElasticSearch default configuration path [{}]\n'.format(
                            self.configuration_directory))
                    subprocess.call('echo ES_PATH_CONF="{}" >> {}'.format(self.configuration_directory, env_file),
                                    shell=True)
                if 'ES_HOME' not in env_str:
                    if stdout:
                        sys.stdout.write('[+] Updating ElasticSearch default home path [{}]\n'.format(
                            self.install_directory))
                    subprocess.call('echo ES_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
        except IOError:
            raise elastic_exceptions.InstallElasticsearchError("Failed to open {} for reading.".format(env_file))
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while creating environment variables in {}; {}".format(env_file, e))

    def _setup_default_elasticsearch_configs(self):
        if self.stdout:
            sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'elasticsearch', 'elasticsearch.yml'),
                    self.configuration_directory)
        try:
            es_config = elastic_configs.ConfigManager(configuration_directory=self.configuration_directory)
        except elastic_exceptions.ReadElasticConfigError:
            raise elastic_exceptions.InstallElasticsearchError("Failed to read elasticsearch config.")
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while reading elasticsearch configs; {}".format(e))
        if self.stdout:
            sys.stdout.write('[+] Setting up JVM default heap settings [{}GB]\n'.format(self.heap_size_gigs))
        es_config.java_initial_memory = int(self.heap_size_gigs)
        es_config.java_maximum_memory = int(self.heap_size_gigs)
        es_config.network_host = self.host
        es_config.http_port = self.port
        try:
            es_config.write_configs()
        except elastic_exceptions.WriteElasticConfigError:
            raise elastic_exceptions.InstallElasticsearchError("Failed to write elasticsearch config.")
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while writing elasticsearch configs; {}".format(e))

    def _update_sysctl(self):
        if self.stdout:
            sys.stdout.write('[+] Setting up Max File Handles [65535] VM Max Map Count [262144] \n')
        try:
            utilities.update_user_file_handle_limits()
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error while setting user file-handle limits; {}".format(e))
        try:
            utilities.update_sysctl(verbose=self.verbose)
        except Exception as e:
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
    def extract_elasticsearch(stdout=False):
        """
        Extract ElasticSearch to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.ELASTICSEARCH_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))
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
                current_password=bootstrap_users_and_passwords['elastic'])
            es_pass_config.set_all_passwords(new_password=self.password, stdout=True)

        if not elastic_profile.ProcessProfiler().is_installed:
            sys.stderr.write('[-] ElasticSearch must be installed and running to bootstrap passwords.\n')
            raise elastic_exceptions.InstallElasticsearchError(
                "Elasticsearch must be installed an running to bootstrap passwords.")
        sys.stdout.write('[+] Creating certificate keystore\n')
        es_config_path = os.path.join(self.configuration_directory, 'config')
        try:
            utilities.makedirs(es_config_path, exist_ok=True)
        except Exception as e:
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
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to install SSL keystores; {}".format(e))
        if not os.path.exists(es_cert_keystore):
            sys.stderr.write('[-] Failed to setup SSL certificate keystore: \noutput: {}\n\t'.format(cert_p_res))
            raise elastic_exceptions.InstallElasticsearchError("Failed to setup SSL keystore; {}".format(cert_p_res))
        keystore_config_path = os.path.join(self.configuration_directory, 'config')
        try:
            utilities.set_ownership_of_file(keystore_config_path,
                                            user='dynamite', group='dynamite')
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to set permissions for {} ; {}".format(keystore_config_path,
                                                                                                e))
        if not elastic_profile.ProcessProfiler().is_running:
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
        sys.stdout.write('[+] Bootstrapping passwords.\n')
        es_password_util = os.path.join(self.install_directory, 'bin', 'elasticsearch-setup-passwords')
        bootstrap_p = subprocess.Popen([es_password_util, 'auto'],
                                       cwd=self.configuration_directory, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, stdin=subprocess.PIPE, env=env_dict)
        try:
            bootstrap_p_res = bootstrap_p.communicate(input=b'y\n')
            if not bootstrap_p_res:
                sys.stderr.write('[-] Failed to setup new passwords\n')
                raise elastic_exceptions.InstallElasticsearchError("Failed to bootstrap password.")
            try:
                if not isinstance(bootstrap_p_res[0], str):
                    setup_from_bootstrap(bootstrap_p_res[0].decode())
                else:
                    setup_from_bootstrap(bootstrap_p_res[0])
            except general_exceptions.ResetPasswordError:
                raise elastic_exceptions.InstallElasticsearchError("Failed to bootstrap password.")
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to bootstrap elasticsearch passwords {}".format(e))


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
    :param verbose: Include output from system utilities
    """
    es_profiler = elastic_profile.ProcessProfiler()
    if es_profiler.is_installed:
        sys.stderr.write('[-] ElasticSearch is already installed. If you wish to re-install, first uninstall.\n')
        raise elastic_exceptions.InstallElasticsearchError(
            "ElasticSearch is already installed. If you wish to re-install, first uninstall.")
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite ElasticSearch requires at-least 6GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes() / (1000 ** 3)
        ))
        raise elastic_exceptions.InstallElasticsearchError(
            "Dynamite ElasticSearch requires at-least 6GB to run currently available [{} GB]")
    es_installer = InstallManager(configuration_directory=configuration_directory,
                                  install_directory=install_directory, log_directory=log_directory,
                                  password=password, heap_size_gigs=heap_size_gigs,
                                  download_elasticsearch_archive=not es_profiler.is_downloaded,
                                  stdout=stdout, verbose=verbose)
    if install_jdk:
        try:
            utilities.download_java(stdout=stdout)
            utilities.extract_java(stdout=stdout)
            utilities.setup_java()
        except Exception as e:
            raise elastic_exceptions.InstallElasticsearchError(
                "General error occurred while attempting to setup Java; {}".format(e))
    if create_dynamite_user:
        utilities.create_dynamite_user(utilities.generate_random_password(50))
    es_installer.setup_elasticsearch()


def uninstall_elasticsearch(stdout=False, prompt_user=True):
    """
    Uninstall ElasticSearch

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    """
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    es_profiler = elastic_profile.ProcessProfiler()
    if not es_profiler.is_installed:
        raise elastic_exceptions.UninstallElasticsearchError("ElasticSearch is not installed.")
    configuration_directory = environment_variables.get('ES_PATH_CONF')
    es_config = elastic_configs.ConfigManager(configuration_directory=configuration_directory)
    if prompt_user:
        sys.stderr.write('[-] WARNING! Removing ElasticSearch Will Delete All Data.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return
    if es_profiler.is_running:
        elastic_process.ProcessManager().stop(stdout=stdout)
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
        if stdout:
            sys.stdout.write('[+] ElasticSearch uninstalled successfully.\n')
    except Exception as e:
        raise elastic_exceptions.UninstallElasticsearchError(
            "General error occurred while attempting to uninstall elasticsearch; {}".format(e))
