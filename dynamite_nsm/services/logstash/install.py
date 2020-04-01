import os
import sys
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
from dynamite_nsm.services.logstash import config as logstash_config
from dynamite_nsm.services.logstash import profile as logstash_profile
from dynamite_nsm.services.logstash import process as logstash_process
from dynamite_nsm.services.elasticsearch import profile as elastic_profile
from dynamite_nsm.services.logstash.synesis import config as synesis_config
from dynamite_nsm.services.logstash.synesis import install as synesis_install
from dynamite_nsm.services.logstash.elastiflow import config as elastiflow_config
from dynamite_nsm.services.logstash.elastiflow import install as elastiflow_install


class InstallManager:
    """
    Provides a simple interface for installing a new Logstash collector with ElastiFlow pipelines
    """

    def __init__(self,
                 configuration_directory,
                 install_directory,
                 log_directory,
                 host='0.0.0.0',
                 elasticsearch_host='localhost',
                 elasticsearch_port=9200,
                 elasticsearch_password='changeme',
                 download_logstash_archive=True,
                 stdout=True,
                 verbose=False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/logstash/)
        :param host: The IP address to listen on (E.G "0.0.0.0")
        :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
        :param elasticsearch_port: A port number for the target elasticsearch instance
        :param elasticsearch_password: The password used for authentication across all builtin ES users
        :param download_logstash_archive: If True, download the LogStash archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include output from system utilities
        """
        self.host = host
        if not elasticsearch_host:
            if elastic_profile.ProcessProfiler().is_installed:
                self.elasticsearch_host = 'localhost'
            else:
                raise Exception("ElasticSearch must either be installed locally, or a remote host must be specified.")
        else:
            self.elasticsearch_host = elasticsearch_host
        self.elasticsearch_port = elasticsearch_port
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.elasticsearch_password = elasticsearch_password
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose
        if download_logstash_archive:
            self.download_logstash(stdout=stdout)
            self.extract_logstash(stdout=stdout)

    def _copy_logstash_files_and_directories(self):
        if self.stdout:
            sys.stdout.write('[+] Copying required LogStash files and directories.\n')
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
        for path in config_paths:
            if self.stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.LOGSTASH_DIRECTORY_NAME, path)),
                    self.configuration_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.LOGSTASH_DIRECTORY_NAME, path)),
                            self.configuration_directory)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            if self.stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.LOGSTASH_DIRECTORY_NAME, path)),
                    self.install_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.LOGSTASH_DIRECTORY_NAME, path)),
                            self.install_directory)
            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))

    def _create_logstash_directories(self):
        if self.stdout:
            sys.stdout.write('[+] Creating logstash install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.install_directory, 'data')), shell=True)

    def _create_logstash_environment_variables(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if 'LS_PATH_CONF' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating LogStash default configuration path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo LS_PATH_CONF="{}" >> {}'.format(self.configuration_directory, env_file), shell=True)
        if 'LS_HOME' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating LogStash default home path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo LS_HOME="{}" >> {}'.format(self.install_directory, env_file), shell=True)

    def _install_logstash_plugins(self):
        if self.stdout:
            sys.stdout.write('[+] Installing Logstash plugins\n')
            sys.stdout.flush()
        if self.verbose:
            subprocess.call('{}/bin/logstash-plugin install logstash-codec-sflow'.format(self.install_directory),
                            shell=True, env=utilities.get_environment_file_dict())
            subprocess.call('{}/bin/logstash-plugin install logstash-codec-netflow'.format(self.install_directory),
                            shell=True, env=utilities.get_environment_file_dict())
            subprocess.call('{}/bin/logstash-plugin install logstash-filter-dns'.format(self.install_directory),
                            shell=True, env=utilities.get_environment_file_dict())

            subprocess.call('{}/bin/logstash-plugin install logstash-filter-geoip'.format(self.install_directory),
                            shell=True, env=utilities.get_environment_file_dict())
            subprocess.call('{}/bin/logstash-plugin install logstash-filter-translate'.format(self.install_directory),
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
            subprocess.call('{}/bin/logstash-plugin install logstash-filter-translate'.format(self.install_directory),
                            shell=True, env=utilities.get_environment_file_dict(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.call('{}/bin/logstash-plugin install logstash-input-beats'.format(self.install_directory),
                            shell=True, env=utilities.get_environment_file_dict(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _setup_default_logstash_configs(self):
        sys.stdout.write('[+] Overwriting default configuration.\n')
        sys.stdout.flush()
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'logstash.yml'),
                    self.configuration_directory)
        ls_config = logstash_config.ConfigManager(configuration_directory=self.configuration_directory)
        if self.stdout:
            sys.stdout.write('[+] Setting up JVM default heap settings [4GB]\n')
            sys.stdout.flush()
        ls_config.java_initial_memory = 4
        ls_config.java_maximum_memory = 4
        ls_config.write_configs()

    def _setup_elastiflow(self):
        ef_install = elastiflow_install.InstallManager(install_directory=os.path.join(
            self.configuration_directory, 'elastiflow')
        )
        ef_install.setup_logstash_elastiflow()
        ef_config = elastiflow_config.ConfigManager()
        ef_config.ipfix_tcp_ipv4_host = self.host
        ef_config.netflow_ipv4_host = self.host
        ef_config.sflow_ipv4_host = self.host
        ef_config.zeek_ipv4_host = self.host
        ef_config.es_host = self.elasticsearch_host + ':' + str(self.elasticsearch_port)
        ef_config.es_passwd = self.elasticsearch_password
        ef_config.write_environment_variables()

    def _setup_synesis(self):
        syn_install = synesis_install.InstallManager(
            install_directory=os.path.join(self.configuration_directory, 'synesis'))
        syn_install.setup_logstash_synesis()
        syn_config = synesis_config.ConfigManager()
        syn_config.suricata_es_host = self.elasticsearch_host + ':' + str(self.elasticsearch_port)
        syn_config.suricata_resolve_ip2host = True
        syn_config.es_passwd = self.elasticsearch_password
        syn_config.write_environment_variables()

    @staticmethod
    def _update_sysctl(stdout=False):
        if stdout:
            sys.stdout.write('[+] Setting up Max File Handles [65535] VM Max Map Count [262144] \n')
        utilities.update_user_file_handle_limits()
        utilities.update_sysctl()

    @staticmethod
    def download_logstash(stdout=False):
        """
        Download Logstash archive

        :param stdout: Print output to console
        """
        for url in open(const.LOGSTASH_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.LOGSTASH_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_logstash(stdout=False):
        """
        Extract Logstash to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.LOGSTASH_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.LOGSTASH_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

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
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'pipelines.yml'),
                    os.path.join(self.configuration_directory, 'pipelines.yml'))
        utilities.set_ownership_of_file(const.CONFIG_PATH, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(const.BIN_PATH, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file('/var/log/dynamite', user='dynamite', group='dynamite')


def install_logstash(configuration_directory, install_directory, log_directory, host='0.0.0.0',
                     elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme',
                     install_jdk=True, create_dynamite_user=True, stdout=False, verbose=False
                     ):
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
    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run Logstash/ElasticSearch
    :param stdout: Print the output to console
    :param verbose: Include output from system utilities
    :return: True, if installation succeeded
    """
    ls_profiler = logstash_profile.ProcessProfiler()
    if ls_profiler.is_installed:
        sys.stderr.write('[-] LogStash is already installed. If you wish to re-install, first uninstall.\n')
        return False
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('[-] WARNING! Dynamite Logstash should have at-least 6GB to run '
                         'currently available [{} GB]\n'.format(utilities.get_memory_available_bytes() / (1000 ** 3)
                                                                ))
        if str(utilities.prompt_input('Continue? [y|N]: ')).lower() != 'y':
            return False
    try:
        ls_installer = InstallManager(configuration_directory, install_directory, log_directory, host=host,
                                      elasticsearch_host=elasticsearch_host, elasticsearch_port=elasticsearch_port,
                                      elasticsearch_password=elasticsearch_password,
                                      download_logstash_archive=not ls_profiler.is_downloaded, stdout=stdout,
                                      verbose=verbose
                                      )
        if install_jdk:
            utilities.download_java(stdout=stdout)
            utilities.extract_java(stdout=stdout)
            utilities.setup_java()
        if create_dynamite_user:
            utilities.create_dynamite_user(utilities.generate_random_password(50))
        ls_installer.setup_logstash()
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install LogStash: ')
        traceback.print_exc(file=sys.stderr)
        return False
    if stdout:
        sys.stdout.write('[+] *** LogStash installed event/alert pipelines. ***\n\n')
        sys.stdout.write('[+] Next, Start your collector: \'dynamite start logstash\'.\n')
        sys.stdout.flush()
    return logstash_profile.ProcessProfiler(stderr=False).is_installed


def uninstall_logstash(stdout=False, prompt_user=True):
    """
    Install Logstash with ElastiFlow & Synesis

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    :return: True, if uninstall succeeded
    """
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('LS_PATH_CONF')
    ls_profiler = logstash_profile.ProcessProfiler()
    ls_config = logstash_config.ConfigManager(configuration_directory=configuration_directory)
    if not ls_profiler.is_installed:
        sys.stderr.write('[-] LogStash is not installed.\n')
        return False
    if prompt_user:
        sys.stderr.write('[-] WARNING! REMOVING LOGSTASH WILL PREVENT ELASTICSEARCH FROM RECEIVING EVENTS.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    if ls_profiler.is_running:
        logstash_process.ProcessManager().stop(stdout=stdout)
    try:
        shutil.rmtree(ls_config.ls_path_conf)
        shutil.rmtree(ls_config.ls_home)
        shutil.rmtree(ls_config.path_logs)
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        for line in open(env_file).readlines():
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
        open(env_file, 'w').write(env_lines)
        if stdout:
            sys.stdout.write('[+] LogStash uninstalled successfully.\n')
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to uninstall LogStash: ')
        traceback.print_exc(file=sys.stderr)
        return False
    return True
