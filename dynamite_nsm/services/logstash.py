import os
import sys
import time
import json
import signal
import shutil
import tarfile
import traceback
import subprocess
from yaml import load, dump
from multiprocessing import Process

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.helpers import synesis
from dynamite_nsm.services.helpers import elastiflow
from dynamite_nsm.services.elasticsearch import ElasticProfiler

CONFIGURATION_DIRECTORY = '/etc/dynamite/logstash/'
INSTALL_DIRECTORY = '/opt/dynamite/logstash/'
LOG_DIRECTORY = '/var/log/dynamite/logstash/'


class LogstashConfigurator:
    """
    Wrapper for configuring logstash.yml and jvm.options
    """

    tokens = {
        'node_name': ('node.name',),
        'path_data': ('path.data',),
        'path_logs': ('path.logs',),
        'pipeline_batch_size': ('pipeline.batch.size',),
        'pipeline_batch_delay': ('pipeline.batch.delay',)
    }

    def __init__(self, configuration_directory):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
        """
        self.configuration_directory = configuration_directory
        self.java_home = None
        self.ls_home = None
        self.ls_path_conf = None
        self.java_initial_memory = None
        self.java_maximum_memory = None

        self.node_name = None
        self.path_data = None
        self.path_logs = None
        self.pipeline_batch_size = None
        self.pipeline_batch_delay = None

        self._parse_environment_file()
        self._parse_jvm_options()
        self._parse_logstashyaml()

    def _parse_logstashyaml(self):

        def set_instance_var_from_token(variable_name, data):
            """
            :param variable_name: The name of the instance variable to update
            :param data: The parsed yaml object
            :return: True if successfully located
            """
            if variable_name not in self.tokens.keys():
                return False
            key_path = self.tokens[variable_name]
            value = data
            try:
                for k in key_path:
                    value = value[k]
                setattr(self, var_name, value)
            except KeyError:
                pass
            return True

        with open(os.path.join(self.configuration_directory, 'logstash.yml'), 'r') as configyaml:
            self.config_data = load(configyaml, Loader=Loader)

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def _parse_jvm_options(self):
        """
        Parses the initial and max heap allocation from jvm.options configuration
        :return: A dictionary containing the initial_memory and maximum_memory allocated to JVM heap
        """
        config_path = os.path.join(self.configuration_directory, 'jvm.options')
        for line in open(config_path).readlines():
            if not line.startswith('#') and '-Xms' in line:
                self.java_initial_memory = line.replace('-Xms', '').strip()
            elif not line.startswith('#') and '-Xmx' in line:
                self.java_maximum_memory = line.replace('-Xmx', '').strip()

    def _parse_environment_file(self):
        """
        Parses the /etc/dynamite/environment file and returns results for JAVA_HOME, LS_PATH_CONF, LS_HOME;
        stores the results in class variables of the same name
        """
        for line in open('/etc/dynamite/environment').readlines():
            if line.startswith('JAVA_HOME'):
                self.java_home = line.split('=')[1].strip()
            elif line.startswith('LS_PATH_CONF'):
                self.ls_path_conf = line.split('=')[1].strip()
            elif line.startswith('LS_HOME'):
                self.ls_home = line.split('=')[1].strip()

    @staticmethod
    def get_elasticsearch_password():
        """
        :return: The password for the given ElasticSearch instance
        """
        elastiflow_config = elastiflow.ElastiflowConfigurator()
        return elastiflow_config.es_passwd

    @staticmethod
    def set_elasticsearch_password(password):
        """
        :param password: The new password
        """
        elastiflow_config = elastiflow.ElastiflowConfigurator()
        synesis_config = synesis.SynesisConfigurator()
        elastiflow_config.es_passwd = password
        synesis_config.es_passwd = password
        elastiflow_config.write_environment_variables()
        synesis_config.write_environment_variables()

    def write_jvm_config(self):
        """
        Overwrites the JVM initial/max memory if settings were updated
        """
        new_output = ''
        for line in open(os.path.join(self.configuration_directory, 'jvm.options')).readlines():
            if not line.startswith('#') and '-Xms' in line:
                new_output += '-Xms' + str(self.java_initial_memory) + 'g'
            elif not line.startswith('#') and '-Xmx' in line:
                new_output += '-Xmx' + str(self.java_maximum_memory) + 'g'
            else:
                new_output += line
            new_output += '\n'

        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        java_config_backup = os.path.join(backup_configurations, 'java.options.backup.{}'.format(
            int(time.time())
        ))
        shutil.copy(os.path.join(self.configuration_directory, 'jvm.options'), java_config_backup)
        open(os.path.join(self.configuration_directory, 'jvm.options'), 'w').write(new_output)

    def write_logstash_config(self):

        def update_dict_from_path(path, value):
            """
            :param path: A tuple representing each level of a nested path in the yaml document
                        ('vars', 'address-groups', 'HOME_NET') = /vars/address-groups/HOME_NET
            :param value: The new value
            :return: None
            """
            partial_config_data = self.config_data
            for i in range(0, len(path) - 1):
                try:
                    partial_config_data = partial_config_data[path[i]]
                except KeyError:
                    pass
            partial_config_data.update({path[-1]: value})

        timestamp = int(time.time())
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        logstash_config_backup = os.path.join(backup_configurations, 'logstash.yml.backup.{}'.format(timestamp))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.copy(os.path.join(self.configuration_directory, 'logstash.yml'), logstash_config_backup)

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        with open(os.path.join(self.configuration_directory, 'logstash.yml'), 'w') as configyaml:
            dump(self.config_data, configyaml, default_flow_style=False)

    def write_configs(self):
        """
        Writes both the JVM and logstash.yaml configurations, backs up originals
        """
        self.write_logstash_config()
        self.write_jvm_config()


class LogstashInstaller:
    """
    Provides a simple interface for installing a new Logstash collector with ElastiFlow pipelines
    """
    def __init__(self,
                 host='0.0.0.0',
                 elasticsearch_host='localhost',
                 elasticsearch_port=9200,
                 elasticsearch_password='changeme',
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY,
                 log_directory=LOG_DIRECTORY,
                 download_logstash_archive=True,
                 stdout=True,
                 verbose=False):
        """
        :param host: The IP address to listen on (E.G "0.0.0.0")
        :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
        :param elasticsearch_port: A port number for the target elasticsearch instance
        :param elasticsearch_password: The password used for authentication across all builtin ES users
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/logstash/)
        :param download_logstash_archive: If True, download the LogStash archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include output from system utilities
        """
        self.host = host
        if not elasticsearch_host:
            if ElasticProfiler().is_installed:
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
        if 'LS_PATH_CONF' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating LogStash default configuration path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo LS_PATH_CONF="{}" >> /etc/dynamite/environment'.format(self.configuration_directory),
                            shell=True)
        if 'LS_HOME' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating LogStash default home path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo LS_HOME="{}" >> /etc/dynamite/environment'.format(self.install_directory),
                            shell=True)

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
        ls_config = LogstashConfigurator(configuration_directory=self.configuration_directory)
        if self.stdout:
            sys.stdout.write('[+] Setting up JVM default heap settings [4GB]\n')
            sys.stdout.flush()
        ls_config.java_initial_memory = 4
        ls_config.java_maximum_memory = 4
        ls_config.write_configs()

    def _setup_elastiflow(self):
        ef_install = elastiflow.ElastiFlowInstaller(install_directory=os.path.join(
            self.configuration_directory, 'elastiflow')
        )
        ef_install.setup_logstash_elastiflow()
        ef_config = elastiflow.ElastiflowConfigurator()
        ef_config.ipfix_tcp_ipv4_host = self.host
        ef_config.netflow_ipv4_host = self.host
        ef_config.sflow_ipv4_host = self.host
        ef_config.zeek_ipv4_host = self.host
        ef_config.es_host = self.elasticsearch_host + ':' + str(self.elasticsearch_port)
        ef_config.es_passwd = self.elasticsearch_password
        ef_config.write_environment_variables()

    def _setup_synesis(self):
        syn_install = synesis.SynesisInstaller(install_directory=os.path.join(self.configuration_directory, 'synesis'))
        syn_install.setup_logstash_synesis()
        syn_config = synesis.SynesisConfigurator()
        syn_config.suricata_es_host = self.elasticsearch_host + ':' + str(self.elasticsearch_port)
        syn_config.suricata_resolve_ip2host = True
        syn_config.suricata_es_passwd = self.elasticsearch_password
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
        utilities.set_ownership_of_file('/etc/dynamite/', user='dynamite', group='dynamite')
        utilities.set_ownership_of_file('/opt/dynamite/', user='dynamite', group='dynamite')
        utilities.set_ownership_of_file('/var/log/dynamite', user='dynamite', group='dynamite')


class LogstashProfiler:
    """
    Interface for determining whether Logstash is installed/configured/running properly.
    """
    def __init__(self, stderr=False):
        """
        :param stderr: Print error messages to console
        """
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_elastiflow_downloaded = self._is_elastiflow_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_elastiflow_installed = self._is_elastiflow_installed(stderr=stderr)
        self.is_configured = self._is_configured(stderr=stderr)
        self.is_running = self._is_running()

    def __str__(self):
        return json.dumps({
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'CONFIGURED': self.is_configured,
            'RUNNING': self.is_running,
        }, indent=1)

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.LOGSTASH_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] Logstash installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_elastiflow_downloaded(stderr):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.ELASTIFLOW_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] Elastiflow installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        ls_home = env_dict.get('LS_HOME')
        if not ls_home:
            if stderr:
                sys.stderr.write('[-] LogStash installation directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(ls_home):
            if stderr:
                sys.stderr.write('[-] LogStash installation directory could not be located at {}.\n'.format(ls_home))
            return False
        ls_home_files_and_dirs = os.listdir(ls_home)
        if 'bin' not in ls_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate LogStash {}/bin directory.\n'.format(ls_home))
            return False
        if 'lib' not in ls_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate LogStash {}/lib directory.\n'.format(ls_home))
            return False
        ls_binaries = os.listdir(os.path.join(ls_home, 'bin'))
        if 'logstash' not in ls_binaries:
            if stderr:
                sys.stderr.write('[-] Could not locate LogStash binary in {}/bin/\n'.format(ls_home))
            return False
        if not utilities.check_user_exists('dynamite'):
            sys.stderr.write('[-] dynamite user was not created.\n')
            return False
        return True

    @staticmethod
    def _is_elastiflow_installed(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        ef_dict_path = env_dict.get('ELASTIFLOW_DICT_PATH')
        syn_dict_path = env_dict.get('SYNLITE_SURICATA_DICT_PATH')
        ef_template_path = env_dict.get('ELASTIFLOW_TEMPLATE_PATH')
        syn_template_path = env_dict.get('SYNLITE_SURICATA_TEMPLATE_PATH')
        ef_geo_ip_db_path = env_dict.get('ELASTIFLOW_GEOIP_DB_PATH')
        ef_definition_path = env_dict.get('ELASTIFLOW_DEFINITION_PATH')
        if not ef_dict_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow dictionary directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        elif not ef_template_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow template directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        elif not ef_geo_ip_db_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow geoip directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        elif not ef_definition_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow definitions directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        elif not syn_dict_path:
            if stderr:
                sys.stderr.write('[-] Synesis dictionary directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        elif not syn_template_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow template directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(ef_dict_path):
            if stderr:
                sys.stderr.write('[-] ElastiFlow dictionary directory could not be located at: '
                                 '{}\n'.format(ef_dict_path))
            return False
        elif not os.path.exists(ef_template_path):
            if stderr:
                sys.stderr.write('[-] ElastiFlow template directory could not be located at: '
                                 '{}\n'.format(ef_template_path))
            return False
        elif not os.path.exists(ef_geo_ip_db_path):
            if stderr:
                sys.stderr.write('[-] ElastiFlow geoip directory could not be located at: {}\n'.format(
                    ef_geo_ip_db_path))
            return False
        elif not os.path.exists(ef_definition_path):
            if stderr:
                sys.stderr.write('[-] ElastiFlow definitions directory could not be located at: {}\n'.format(
                    ef_definition_path))
            return False
        elif not os.path.exists(syn_dict_path):
            if stderr:
                sys.stderr.write('[-] Synesis dictionary directory could not be located at: {}\n'.format(
                    ef_definition_path))
            return False
        elif not os.path.exists(syn_template_path):
            if stderr:
                sys.stderr.write('[-] Synesis template directory could not be located at: {}\n'.format(
                    ef_definition_path))
            return False
        return True

    @staticmethod
    def _is_configured(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        ls_path_conf = env_dict.get('LS_PATH_CONF')
        if not ls_path_conf:
            if stderr:
                sys.stderr.write('[-] LogStash configuration directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(os.path.join(ls_path_conf, 'logstash.yml')):
            if stderr:
                sys.stderr.write('[-] Could not locate logstash.yml in {}\n'.format(ls_path_conf))
            return False
        if not os.path.exists(os.path.join(ls_path_conf, 'jvm.options')):
            if stderr:
                sys.stderr.write('[-] Could not locate jvm.options in {}\n'.format(ls_path_conf))
            return False
        try:
            LogstashConfigurator(configuration_directory=ls_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable logstash.yml or jvm.options \n')
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return LogstashProcess().status()['RUNNING']
        except Exception:
            return False

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running
        }


class LogstashProcess:
    """
    An interface for start|stop|status|restart of the LogStash process
    """
    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('LS_PATH_CONF')
        self.config = LogstashConfigurator(self.configuration_directory)

        if not os.path.exists('/var/run/dynamite/logstash/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/logstash/'), shell=True)

        utilities.set_ownership_of_file('/var/run/dynamite', user='dynamite', group='dynamite')
        try:
            self.pid = int(open('/var/run/dynamite/logstash/logstash.pid').read()) + 1
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the LogStash process
        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.pid = -1

        def start_shell_out():
            command = 'runuser -l dynamite -c "{} {}/bin/logstash ' \
                      '--path.settings={} &>/dev/null & echo \$! > /var/run/dynamite/logstash/logstash.pid"'.format(
                utilities.get_environment_file_str(), self.config.ls_home, self.config.ls_path_conf)
            subprocess.call(command, shell=True, cwd=self.config.ls_home)
        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] Logstash is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting Logstash on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/logstash/logstash.pid') as f:
                    self.pid = int(f.read()) + 1
                start_message = '[+] [Attempt: {}] Starting LogStash on PID [{}]\n'.format(retry + 1, self.pid)
                if stdout:
                    sys.stdout.write(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(3)
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
        Stop the LogStash process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop LogStash [{}]\n'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGKILL
                else:
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)
                alive = utilities.check_pid(self.pid)
            except Exception as e:
                sys.stderr.write('[-] An error occurred while attempting to stop LogStash: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the LogStash process

        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

    def status(self):
        """
        Check the status of the LogStash process

        :return: A dictionary containing the run status and relevant configuration options
        """
        log_path = os.path.join(self.config.path_logs, 'logstash-plain.log')

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'USER': 'dynamite',
            'LOGS': log_path
        }


def change_logstash_elasticsearch_password(password='changeme', prompt_user=True, stdout=False):
    if prompt_user:
        resp = utilities.prompt_input(
            'Changing the LogStash password can cause LogStash to lose communication with ElasticSearch. '
            'Are you sure you wish to continue? [no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    LogstashConfigurator(configuration_directory=CONFIGURATION_DIRECTORY).set_elasticsearch_password(password=password)
    return LogstashProcess().restart(stdout=True)


def install_logstash(host='0.0.0.0',
                     elasticsearch_host='localhost',
                     elasticsearch_port=9200,
                     elasticsearch_password='changeme',
                     install_jdk=True,
                     create_dynamite_user=True,
                     stdout=False,
                     verbose=False
                     ):
    """
    Install Logstash/ElastiFlow
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
    ls_profiler = LogstashProfiler()
    if ls_profiler.is_installed:
        sys.stderr.write('[-] LogStash is already installed. If you wish to re-install, first uninstall.\n')
        return False
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('[-] WARNING! Dynamite Logstash should have at-least 6GB to run '
                         'currently available [{} GB]\n'.format(utilities.get_memory_available_bytes()/(1000 ** 3)
        ))
        if str(utilities.prompt_input('Continue? [y|N]: ')).lower() != 'y':
            return False
    try:
        ls_installer = LogstashInstaller(host=host,
                                         elasticsearch_host=elasticsearch_host,
                                         elasticsearch_port=elasticsearch_port,
                                         elasticsearch_password=elasticsearch_password,
                                         download_logstash_archive=not ls_profiler.is_downloaded,
                                         stdout=stdout,
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
    return LogstashProfiler(stderr=False).is_installed


def uninstall_logstash(stdout=False, prompt_user=True):
    """
    Uninstall Logstash/ElastiFlow

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    :return: True, if uninstall succeeded
    """
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('LS_PATH_CONF')
    ls_profiler = LogstashProfiler()
    ls_config = LogstashConfigurator(configuration_directory=configuration_directory)
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
        LogstashProcess().stop(stdout=stdout)
    try:
        shutil.rmtree(ls_config.ls_path_conf)
        shutil.rmtree(ls_config.ls_home)
        shutil.rmtree(ls_config.path_logs)
        shutil.rmtree('/tmp/dynamite/install_cache/', ignore_errors=True)
        env_lines = ''
        for line in open('/etc/dynamite/environment').readlines():
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
        open('/etc/dynamite/environment', 'w').write(env_lines)
        if stdout:
            sys.stdout.write('[+] LogStash uninstalled successfully.\n')
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to uninstall LogStash: ')
        traceback.print_exc(file=sys.stderr)
        return False
    return True
