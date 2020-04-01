import os
import sys
import time
import shutil
import tarfile
import traceback
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
from dynamite_nsm.services.elasticsearch import config as elastic_configs
from dynamite_nsm.services.elasticsearch import process as elastic_process
from dynamite_nsm.services.elasticsearch import profile as elastic_profile


class InstallManager:
    """
    Provides a simple interface for installing a new ElasticSearch node
    """

    def __init__(self, configuration_directory, install_directory, log_directory, host='0.0.0.0', port=9200,
                 password='changeme', download_elasticsearch_archive=True, stdout=False, verbose=False,
                 ):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/elasticsearch/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/elasticsearch/)
        :param: host: The IP address to listen on (E.G "0.0.0.0")
        :param: port: The port that the ES API is bound to (E.G 9200)
        :param: password: The password used for authentication across all builtin users
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
        self.stdout = stdout
        self.verbose = verbose
        if download_elasticsearch_archive:
            self.download_elasticsearch(stdout=stdout)
            self.extract_elasticsearch(stdout=stdout)

    def _create_elasticsearch_directories(self):
        if self.stdout:
            sys.stdout.write('[+] Creating elasticsearch install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.install_directory, 'data')), shell=True)

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
        for path in config_paths:
            if self.stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                    self.configuration_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                            self.configuration_directory)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            if self.stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                    self.install_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                            self.install_directory)
            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))

    def _create_elasticsearch_environment_variables(self, stdout=False):
        if 'ES_PATH_CONF' not in open('/etc/dynamite/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating ElasticSearch default configuration path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo ES_PATH_CONF="{}" >> /etc/dynamite/environment'.format(self.configuration_directory),
                            shell=True)
        if 'ES_HOME' not in open('/etc/dynamite/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating ElasticSearch default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo ES_HOME="{}" >> /etc/dynamite/environment'.format(self.install_directory),
                            shell=True)

    def _setup_default_elasticsearch_configs(self):
        if self.stdout:
            sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'elasticsearch', 'elasticsearch.yml'),
                    self.configuration_directory)
        es_config = elastic_configs.ConfigManager(configuration_directory=self.configuration_directory)
        if self.stdout:
            sys.stdout.write('[+] Setting up JVM default heap settings [4GB]\n')
        es_config.java_initial_memory = 4
        es_config.java_maximum_memory = 4
        es_config.network_host = self.host
        es_config.http_port = self.port
        es_config.write_configs()

    def _update_sysctl(self):
        if self.stdout:
            sys.stdout.write('[+] Setting up Max File Handles [65535] VM Max Map Count [262144] \n')
        utilities.update_user_file_handle_limits()
        utilities.update_sysctl(verbose=self.verbose)

    @staticmethod
    def download_elasticsearch(stdout=False):
        """
        Download ElasticSearch archive

        :param stdout: Print output to console
        """
        for url in open(const.ELASTICSEARCH_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.ELASTICSEARCH_ARCHIVE_NAME, stdout=stdout):
                break

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
        utilities.set_ownership_of_file('/etc/dynamite/', user='dynamite', group='dynamite')
        utilities.set_ownership_of_file('/opt/dynamite/', user='dynamite', group='dynamite')
        utilities.set_ownership_of_file('/var/log/dynamite', user='dynamite', group='dynamite')
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
            return es_pass_config.set_all_passwords(new_password=self.password, stdout=True)

        if not elastic_profile.ProcessProfiler().is_installed:
            sys.stderr.write('[-] ElasticSearch must be installed and running to bootstrap passwords.\n')
            return False
        sys.stdout.write('[+] Creating certificate keystore\n')
        subprocess.call('mkdir -p {}'.format(os.path.join(self.configuration_directory, 'config')), shell=True)
        es_cert_util = os.path.join(self.install_directory, 'bin', 'elasticsearch-certutil')
        es_cert_keystore = os.path.join(self.configuration_directory, 'config', 'elastic-certificates.p12')
        cert_p = subprocess.Popen([es_cert_util, 'cert', '-out', es_cert_keystore, '-pass', ''],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE,
                                  env=env_dict)
        cert_p_res = cert_p.communicate()
        if not os.path.exists(es_cert_keystore):
            sys.stderr.write('[-] Failed to setup SSL certificate keystore: \noutput: {}\n\t'.format(cert_p_res))
            return False
        utilities.set_ownership_of_file(os.path.join(self.configuration_directory, 'config'),
                                        user='dynamite', group='dynamite')
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
        bootstrap_p_res = bootstrap_p.communicate(input=b'y\n')
        if not bootstrap_p_res:
            sys.stderr.write('[-] Failed to setup new passwords\n')
            return False
        if not isinstance(bootstrap_p_res[0], str):
            return setup_from_bootstrap(bootstrap_p_res[0].decode())
        else:
            return setup_from_bootstrap(bootstrap_p_res[0])


def install_elasticsearch(configuration_directory, install_directory, log_directory, password='changeme',
                          install_jdk=True, create_dynamite_user=True, stdout=True, verbose=False):
    """
    Install ElasticSearch
    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
    :param install_directory: Path to the install directory (E.G /opt/dynamite/elasticsearch/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/elasticsearch/)
    :param password: The password used for authentication across all builtin users
    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run Logstash/ElasticSearch
    :param stdout: Print the output to console
    :param verbose: Include output from system utilities
    :return: True, if installation succeeded
    """
    es_profiler = elastic_profile.ProcessProfiler()
    if es_profiler.is_installed:
        sys.stderr.write('[-] ElasticSearch is already installed. If you wish to re-install, first uninstall.\n')
        return False
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite ElasticSearch requires at-least 6GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes() / (1000 ** 3)
        ))
        return False
    try:
        es_installer = InstallManager(configuration_directory=configuration_directory,
                                      install_directory=install_directory, log_directory=log_directory,
                                      password=password, download_elasticsearch_archive=not es_profiler.is_downloaded,
                                      stdout=stdout, verbose=verbose)
        if install_jdk:
            utilities.download_java(stdout=stdout)
            utilities.extract_java(stdout=stdout)
            utilities.setup_java()
        if create_dynamite_user:
            utilities.create_dynamite_user(utilities.generate_random_password(50))
        es_installer.setup_elasticsearch()
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install ElasticSearch: ')
        traceback.print_exc(file=sys.stderr)
        return False
    if stdout:
        sys.stdout.write('[+] *** ElasticSearch installed successfully. ***\n\n')
        sys.stdout.write('[+] Next, Start your cluster: \'dynamite start elasticsearch\'.\n')
    sys.stdout.flush()
    return elastic_profile.ProcessProfiler(stderr=False).is_installed


def uninstall_elasticsearch(stdout=False, prompt_user=True):
    """
    Uninstall ElasticSearch

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    :return: True, if uninstall succeeded
    """
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('ES_PATH_CONF')
    es_profiler = elastic_profile.ProcessProfiler()
    es_config = elastic_configs.ConfigManager(configuration_directory=configuration_directory)
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
        elastic_process.ProcessManager().stop(stdout=stdout)
    try:
        shutil.rmtree(es_config.configuration_directory)
        shutil.rmtree(es_config.es_home)
        shutil.rmtree(es_config.path_logs)
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        for line in open(os.path.join(const.CONFIG_PATH, 'environment')).readlines():
            if 'ES_PATH_CONF' in line:
                continue
            elif 'ES_HOME' in line:
                continue
            elif line.strip() == '':
                continue
            env_lines += line.strip() + '\n'
        open(env_file, 'w').write(env_lines)
        if stdout:
            sys.stdout.write('[+] ElasticSearch uninstalled successfully.\n')
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to uninstall ElasticSearch: ')
        traceback.print_exc(file=sys.stderr)
        return False
    return True
