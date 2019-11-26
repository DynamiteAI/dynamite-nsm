import os
import sys
import json
import time
import base64
import signal
import shutil
import tarfile
import traceback
import subprocess
from multiprocessing import Process

from dynamite_nsm import const
from dynamite_nsm import utilities

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

CONFIGURATION_DIRECTORY = '/etc/dynamite/elasticsearch/'
INSTALL_DIRECTORY = '/opt/dynamite/elasticsearch/'
LOG_DIRECTORY = '/var/log/dynamite/elasticsearch/'


class ElasticConfigurator:
    """
    Wrapper for configuring elasticsearch.yml and jvm.options
    """
    def __init__(self, configuration_directory):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
        """
        self.configuration_directory = configuration_directory
        self.es_config_options = self._parse_elasticyaml()
        self.jvm_config_options = self._parse_jvm_options()
        self.java_home = None
        self.es_home = None
        self.es_path_conf = None
        self._parse_environment_file()

    def _parse_elasticyaml(self):
        """
        Parse elasticsearch.yml, return a object representing the config
        :return: A dictionary of config options and their values
        """
        es_config_options = {}
        config_path = os.path.join(self.configuration_directory, 'elasticsearch.yml')
        if not os.path.exists(config_path):
            return es_config_options
        for line in open(config_path).readlines():
            if not line.startswith('#') and ':' in line:
                if line.startswith('discovery.seed_hosts:'):
                    k = 'discovery.seed_hosts'
                    v = json.loads(line.replace('discovery.seed_hosts:', '').strip())
                    es_config_options[k] = v
                elif line.startswith('cluster.initial_master_nodes:'):
                    k = 'cluster.initial_master_nodes'
                    v = json.loads(line.replace('cluster.initial_master_nodes:', '').strip())
                    es_config_options[k] = v
                else:
                    k, v = line.strip().split(':')
                    es_config_options[k] = str(v).strip().replace('"', '').replace("'", '')
        return es_config_options

    def _parse_jvm_options(self):
        """
        Parses the initial and max heap allocation from jvm.options configuration
        :return: A dictionary containing the initial_memory and maximum_memory allocated to JVM heap
        """
        jvm_options = {}
        config_path = os.path.join(self.configuration_directory, 'jvm.options')
        if not os.path.exists(config_path):
            return jvm_options
        for line in open(config_path).readlines():
            if not line.startswith('#') and '-Xms' in line:
                jvm_options['initial_memory'] = line.replace('-Xms', '').strip()
            elif not line.startswith('#') and '-Xmx' in line:
                jvm_options['maximum_memory'] = line.replace('-Xmx', '').strip()
        return jvm_options

    def _parse_environment_file(self):
        """
        Parses the /etc/dynamite/environment file and returns results for JAVA_HOME, ES_PATH_CONF, ES_HOME;
        stores the results in class variables of the same name
        """
        for line in open('/etc/dynamite/environment').readlines():
            if line.startswith('JAVA_HOME'):
                self.java_home = line.split('=')[1].strip()
            elif line.startswith('ES_PATH_CONF'):
                self.es_path_conf = line.split('=')[1].strip()
            elif line.startswith('ES_HOME'):
                self.es_home = line.split('=')[1].strip()

    def _overwrite_jvm_options(self):
        """
        Overwrites the JVM initial/max memory if settings were updated
        """
        new_output = ''
        for line in open(os.path.join(self.configuration_directory, 'jvm.options')).readlines():
            if not line.startswith('#') and '-Xms' in line:
                new_output += '-Xms' + self.jvm_config_options['initial_memory']
            elif not line.startswith('#') and '-Xmx' in line:
                new_output += '-Xmx' + self.jvm_config_options['maximum_memory']
            else:
                new_output += line
            new_output += '\n'
        open(os.path.join(self.configuration_directory, 'jvm.options'), 'w').write(new_output)

    def get_cluster_name(self):
        """
        :return: The name of the ElasticSearch cluster
        """
        return self.es_config_options.get('cluster.name')

    def get_network_host(self):
        """
        :return: The server that the cluster is running on
        """
        return self.es_config_options.get('network.host')

    def get_network_port(self):
        """
        :return: The port that the cluster is running on
        """
        return self.es_config_options.get('http.port')

    def get_node_name(self):
        """
        :return: The name of the ElasticSearch node
        """
        return self.es_config_options.get('node.name')

    def get_data_path(self):
        """
        :return: The directory where data is being stored
        """
        return self.es_config_options.get('path.data')

    def get_log_path(self):
        """
        :return: The directory logs are being stored in
        """
        return self.es_config_options.get('path.logs')

    def get_discovery_seed_hosts(self):
        """
        :return: A list of hosts also in the cluster
        """
        return self.es_config_options.get('discovery.seed_hosts')

    def get_jvm_initial_memory(self):
        """
        :return: The initial amount of memory the JVM heap allocates
        """
        return self.jvm_config_options.get('initial_memory')

    def get_jvm_maximum_memory(self):
        """
        :return: The maximum amount of memory the JVM heap allocates
        """
        return self.jvm_config_options.get('maximum_memory')

    def set_cluster_name(self, name):
        """
        :param name: The name of the cluster
        """
        self.es_config_options['cluster.name'] = name

    def set_network_host(self, host='localhost'):
        """
        :param host: The IP address for ElasticSearch service to listen on
        """
        self.es_config_options['network.host'] = host

    def set_network_port(self, port=9200):
        """
        :param port: The port number of the for ElasticSearch service to listen on
        """
        self.es_config_options['http.port'] = str(port)

    def set_node_name(self, name):
        """
        :param name: The name of the ElasticSearch node
        """
        self.es_config_options['node.name'] = name
        self.es_config_options['cluster.initial_master_nodes'] = [name]

    def set_data_path(self, path):
        """
        :param path: The path to the ElasticSearch node data
        """
        self.es_config_options['path.data'] = path

    def set_log_path(self, path):
        """
        :param path: The path to the log directory
        """
        self.es_config_options['path.logs'] = path

    def set_discovery_seed_host(self, host_list):
        """
        :param host_list: A list of hosts also in the cluster
        """
        if not isinstance(host_list, list):
            raise TypeError("host_list must be of type: 'list'")
        self.es_config_options['discovery.seed_hosts'] = host_list

    def set_jvm_initial_memory(self, gigs):
        """
        :param gigs: The amount of initial memory (In Gigabytes) for the JVM to allocate to the heap
        """
        self.jvm_config_options['initial_memory'] = str(int(gigs)) + 'g'

    def set_jvm_maximum_memory(self, gigs):
        """
        :param gigs: The amount of maximum memory (In Gigabytes) for the JVM to allocate to the heap
        """
        self.jvm_config_options['maximum_memory'] = str(int(gigs)) + 'g'

    def write_configs(self):
        """
        Write (and backs-up) elasticsearch.yml and jvm.option configurations
        """
        timestamp = int(time.time())
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        es_config_backup = os.path.join(backup_configurations, 'elasticsearch.yml.backup.{}'.format(timestamp))
        java_config_backup = os.path.join(backup_configurations, 'java.options.backup.{}'.format(
            timestamp
        ))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.move(os.path.join(self.configuration_directory, 'elasticsearch.yml'), es_config_backup)
        shutil.copy(os.path.join(self.configuration_directory, 'jvm.options'), java_config_backup)
        with open(os.path.join(self.configuration_directory, 'elasticsearch.yml'), 'a') as elastic_search_config_obj:
            for k, v in self.es_config_options.items():
                if k == 'discovery.seed_hosts':
                    elastic_search_config_obj.write('{}: {}\n'.format(k, json.dumps(v)))
                elif k == 'cluster.initial_master_nodes':
                    elastic_search_config_obj.write('{}: {}\n'.format(k, json.dumps(v)))
                else:
                    elastic_search_config_obj.write('{}: {}\n'.format(k, v))
        self._overwrite_jvm_options()


class ElasticPasswordConfigurator:
    """
    Provides a basic interface for resetting ElasticSearch passwords
    """
    def __init__(self, auth_user, current_password):
        self.auth_user = auth_user
        self.current_password = current_password
        self.env_vars = utilities.get_environment_file_dict()

    def _set_user_password(self, user, password, stdout=False):
        if stdout:
            sys.stdout.write('[+] Updating password for {}\n'.format(user))
        es_config = ElasticConfigurator(configuration_directory=self.env_vars.get('ES_PATH_CONF'))
        try:
            try:
                base64string = base64.b64encode('%s:%s' % (self.auth_user, self.current_password))
            except TypeError:
                encoded_bytes = '{}:{}'.format(self.auth_user, self.current_password).encode('utf-8')
                base64string = base64.b64encode(encoded_bytes).decode('utf-8')
            url_request = Request(
                url='http://{}:{}/_xpack/security/user/{}/_password'.format(
                    es_config.get_network_host(),
                    es_config.get_network_port(),
                    user
                ),
                data=json.dumps({'password': password}),
                headers={'Content-Type': 'application/json', 'kbn-xsrf': True}
            )
            url_request.add_header("Authorization", "Basic %s" % base64string)
            try:
                urlopen(url_request)
            except TypeError:
                urlopen(url_request, data=json.dumps({'password': password}).encode('utf-8'))
        except HTTPError as e:
            if e.code != 200:
                sys.stderr.write('[-] Failed to update {} password - [{}]\n'.format(user, e))
            return False
        return True

    def set_apm_system_password(self, new_password, stdout=False):
        """
        Reset the builtin apm_system user

        :param new_password: The new password
        :param stdout: Print status to stdout
        :return: True, if successfully reset
        """
        return self._set_user_password('apm_system', new_password, stdout=stdout)

    def set_beats_password(self, new_password, stdout=False):
        """
        Reset the builtin beats user

        :param new_password: The new password
        :param stdout: Print status to stdout
        :return: True, if successfully reset
        """
        return self._set_user_password('beats_system', new_password, stdout=stdout)

    def set_elastic_password(self, new_password, stdout=False):
        """
        Reset the builtin elastic user

        :param new_password: The new password
        :param stdout: Print status to stdout
        :return: True, if successfully reset
        """
        return self._set_user_password('elastic', new_password, stdout=stdout)

    def set_kibana_password(self, new_password, stdout=False):
        """
        Reset the builtin kibana user

        :param new_password: The new password
        :param stdout: Print status to stdout
        :return: True, if successfully reset
        """
        return self._set_user_password('kibana', new_password, stdout=stdout)

    def set_logstash_system_password(self, new_password, stdout=False):
        """
        Reset the builtin logstash user

        :param new_password: The new password
        :param stdout: Print status to stdout
        :return: True, if successfully reset
        """
        return self._set_user_password('logstash_system', new_password, stdout=stdout)

    def set_remote_monitoring_password(self, new_password, stdout=False):
        """
        Reset the builtin remote_monitoring_user user

        :param new_password: The new password
        :param stdout: Print status to stdout
        :return: True, if successfully reset
        """
        return self._set_user_password('remote_monitoring_user', new_password, stdout=stdout)

    def set_all_passwords(self, new_password, stdout=False):
        """
        Reset all builtin user passwords

        :param new_password: The new password
        :param stdout: Print status to stdout
        :return: True, if successfully reset
        """
        r = self.set_apm_system_password(new_password, stdout=stdout)
        r2 = self.set_remote_monitoring_password(new_password, stdout=stdout)
        r3 = self.set_logstash_system_password(new_password, stdout=stdout)
        r4 = self.set_kibana_password(new_password, stdout=stdout)
        r5 = self.set_beats_password(new_password, stdout=stdout)
        r6 = self.set_elastic_password(new_password, stdout=stdout)
        return r and r2 and r3 and r4 and r5 and r6


class ElasticInstaller:
    """
    Provides a simple interface for installing a new ElasticSearch node
    """

    def __init__(self,
                 host='0.0.0.0',
                 port=9200,
                 password='changeme',
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY,
                 log_directory=LOG_DIRECTORY):
        """
        :param: host: The IP address to listen on (E.G "0.0.0.0")
        :param: port: The port that the ES API is bound to (E.G 9200)
        :param: password: The password used for authentication across all builtin users
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/elasticsearch/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/f/)
        """

        self.host = host
        self.port = port
        self.password = password
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory

    def _create_elasticsearch_directories(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating elasticsearch install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.install_directory, 'data')), shell=True)

    def _copy_elasticsearch_files_and_directories(self, stdout=False):
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
            if stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                    self.configuration_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.ELASTICSEARCH_DIRECTORY_NAME, path)),
                            self.configuration_directory)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            if stdout:
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

    def _setup_default_elasticsearch_configs(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'elasticsearch', 'elasticsearch.yml'),
                    self.configuration_directory)
        es_config = ElasticConfigurator(configuration_directory=self.configuration_directory)
        if stdout:
            sys.stdout.write('[+] Setting up JVM default heap settings [4GB]\n')
        es_config.set_jvm_initial_memory(4)
        es_config.set_jvm_maximum_memory(4)
        es_config.set_network_host(self.host)
        es_config.set_network_port(self.port)
        es_config.write_configs()

    def _update_sysctl(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Setting up Max File Handles [65535] VM Max Map Count [262144] \n')
        utilities.update_user_file_handle_limits()
        utilities.update_sysctl()

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

    def setup_elasticsearch(self, stdout=False):
        """
        Create required directories, files, and variables to run ElasticSearch successfully;
        Setup Java environment

        :param stdout: Print output to console
        """
        self._create_elasticsearch_directories(stdout=stdout)
        self._copy_elasticsearch_files_and_directories(stdout=stdout)
        self._create_elasticsearch_environment_variables(stdout=stdout)
        self._setup_default_elasticsearch_configs(stdout=stdout)
        self._update_sysctl(stdout=stdout)
        utilities.set_ownership_of_file('/etc/dynamite/')
        utilities.set_ownership_of_file('/opt/dynamite/')
        utilities.set_ownership_of_file('/var/log/dynamite')
        self.setup_passwords(stdout=stdout)

    def setup_passwords(self, stdout=False):
        env_dict = utilities.get_environment_file_dict()

        def setup_from_bootstrap(s):
            bootstrap_users_and_passwords = {}
            for line in s.split('\n'):
                if 'PASSWORD' in line:
                    _, user, _, password = line.split(' ')
                    if not isinstance(password, str):
                        password = password.decode()
                    bootstrap_users_and_passwords[user] = password
            es_pass_config = ElasticPasswordConfigurator(
                auth_user='elastic',
                current_password=bootstrap_users_and_passwords['elastic'])
            return es_pass_config.set_all_passwords(new_password=self.password, stdout=True)

        if not ElasticProfiler().is_installed:
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
        utilities.set_ownership_of_file(os.path.join(self.configuration_directory, 'config'))
        if not ElasticProfiler().is_running:
            ElasticProcess().start(stdout=stdout)
            sys.stdout.flush()
            while not ElasticProfiler().is_listening:
                if stdout:
                    sys.stdout.write('[+] Waiting for ElasticSearch API to become accessible.\n')
                time.sleep(5)
            if stdout:
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


class ElasticProfiler:
    """
    Interface for determining whether ElasticSearch is installed/configured/running properly.
    """
    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_configured = self._is_configured(stderr=stderr)
        self.is_running = self._is_running()
        self.is_listening = self._is_listening(stderr=stderr)

    def __str__(self):
        return json.dumps({
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'CONFIGURED': self.is_configured,
            'RUNNING': self.is_running,
            'LISTENING': self.is_listening
        }, indent=1)

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] ElasticSearch installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        try:
            env_dict = utilities.get_environment_file_dict()
        except IOError:
            if stderr:
                sys.stderr.write('[-] ElasticSearch environment variables haven\'t been created.\n')
            return False
        es_home = env_dict.get('ES_HOME')
        if not es_home:
            if stderr:
                sys.stderr.write('[-] ElasticSearch installation directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(es_home):
            if stderr:
                sys.stderr.write('[-] ElasticSearch installation directory could not be located at {}.\n'.format(
                    es_home))
            return False
        es_home_files_and_dirs = os.listdir(es_home)
        if 'bin' not in es_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate ElasticSearch {}/bin directory.\n'.format(es_home))
            return False
        if 'lib' not in es_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate ElasticSearch {}/lib directory.\n'.format(es_home))
            return False
        es_binaries = os.listdir(os.path.join(es_home, 'bin'))
        if 'elasticsearch' not in es_binaries:
            if stderr:
                sys.stderr.write('[-] Could not locate ElasticSearch binary in {}/bin/\n'.format(es_home))
            return False
        return True

    @staticmethod
    def _is_configured(stderr=False):
        try:
            env_dict = utilities.get_environment_file_dict()
        except IOError:
            if stderr:
                sys.stderr.write('[-] ElasticSearch environment variables haven\'t been created.\n')
            return False
        es_path_conf = env_dict.get('ES_PATH_CONF')
        if not es_path_conf:
            if stderr:
                sys.stderr.write('[-] ElasticSearch configuration directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(os.path.join(es_path_conf, 'elasticsearch.yml')):
            if stderr:
                sys.stderr.write('[-] Could not locate elasticsearch.yml in {}'.format(es_path_conf))
            return False
        if not os.path.exists(os.path.join(es_path_conf, 'jvm.options')):
            if stderr:
                sys.stderr.write('[-] Could not locate jvm.options in {}'.format(es_path_conf))
            return False
        try:
            ElasticConfigurator(configuration_directory=es_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable elasticsearch.yml or jvm.options \n')
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return ElasticProcess().status()['RUNNING']
        except Exception:
            return False

    @staticmethod
    def _is_listening(stderr=False):
        try:
            env_dict = utilities.get_environment_file_dict()
        except IOError:
            if stderr:
                sys.stderr.write('[-] ElasticSearch environment variables haven\'t been created.\n')
            return False
        es_path_conf = env_dict.get('ES_PATH_CONF')
        if not es_path_conf:
            if stderr:
                sys.stderr.write('[-] ElasticSearch configuration directory could not be located in /etc/dynamite/environment.\n')
            return False
        if not os.path.exists(os.path.join(es_path_conf, 'elasticsearch.yml')):
            if stderr:
                sys.stderr.write('[-] Could not locate elasticsearch.yml in {}\n'.format(es_path_conf))
            return False
        if not os.path.exists(os.path.join(es_path_conf, 'jvm.options')):
            if stderr:
                sys.stderr.write('[-] Could not locate jvm.options in {}\n'.format(es_path_conf))
            return False
        try:
            es_config = ElasticConfigurator(configuration_directory=es_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable elasticsearch.yml or jvm.options \n')
            return False
        host = es_config.get_network_host()
        port = es_config.get_network_port()
        if host.strip() == '0.0.0.0':
            host = 'localhost'
        return utilities.check_socket(host, port)

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
            'LISTENING': self.is_listening
        }


class ElasticProcess:
    """
    An interface for start|stop|status|restart of the ElasticSearch process
    """
    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('ES_PATH_CONF')
        self.config = ElasticConfigurator(self.configuration_directory)
        try:
            self.pid = int(open('/var/run/dynamite/elasticsearch/elasticsearch.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the ElasticSearch process
        :param stdout: Print output to console
        :return: True, if started successfully
        """
        def start_shell_out():
            subprocess.call('runuser -l dynamite -c "{} {}/bin/elasticsearch '
                            '-p /var/run/dynamite/elasticsearch/elasticsearch.pid --quiet &>/dev/null &"'.format(
                utilities.get_environment_file_str(), self.config.es_home), shell=True)
        if not os.path.exists('/var/run/dynamite/elasticsearch/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/elasticsearch/'), shell=True)
        utilities.set_ownership_of_file('/var/run/dynamite')

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] ElasticSearch is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting ElasticSearch on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/elasticsearch/elasticsearch.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting ElasticSearch on PID [{}]\n'.format(retry + 1, self.pid)
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
                    sys.stdout.write('[+] Attempting to stop ElasticSearch [{}]\n'.format(self.pid))
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
                sys.stderr.write('[-] An error occurred while attempting to stop ElasticSearch: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the ElasticSearch process

        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

    def status(self):
        """
        Check the status of the ElasticSearch process

        :return: A dictionary containing the run status and relevant configuration options
        """
        log_path = os.path.join(self.config.get_log_path(), self.config.get_cluster_name() + '.log')

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'USER': 'dynamite',
            'LOGS': log_path
        }


def change_elasticsearch_password(old_password, password='changeme', stdout=False):
    if not ElasticProcess().start():
        sys.stderr.write('[-] Could not start ElasticSearch Process. Password reset failed.')
        return False
    while not ElasticProfiler().is_listening:
        if stdout:
            sys.stdout.write('[+] Waiting for ElasticSearch API to become accessible.\n')
        time.sleep(5)
    if stdout:
        sys.stdout.write('[+] ElasticSearch API is up.\n')
        sys.stdout.write('[+] Sleeping for 10 seconds, while ElasticSearch API finishes booting.\n')
        sys.stdout.flush()
    time.sleep(10)
    es_pw_config = ElasticPasswordConfigurator(
        'elastic', current_password=old_password)
    return es_pw_config.set_all_passwords(password, stdout=stdout)


def install_elasticsearch(password='changeme', install_jdk=True, create_dynamite_user=True, stdout=False):
    """
    Install ElasticSearch

    :param password: The password used for authentication across all builtin users
    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run Logstash/ElasticSearch
    :param stdout: Print the output to console
    :return: True, if installation succeeded
    """
    es_profiler = ElasticProfiler()
    if es_profiler.is_installed:
        sys.stderr.write('[-] ElasticSearch is already installed. If you wish to re-install, first uninstall.\n')
        return False
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite ElasticSearch requires at-least 6GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes()/(1000 ** 3)
        ))
        return False
    try:
        es_installer = ElasticInstaller(password=password)
        if install_jdk:
            utilities.download_java(stdout=True)
            utilities.extract_java(stdout=True)
            utilities.setup_java()
        if create_dynamite_user:
            utilities.create_dynamite_user(utilities.generate_random_password(50))
        es_installer.download_elasticsearch(stdout=True)
        es_installer.extract_elasticsearch(stdout=True)
        es_installer.setup_elasticsearch(stdout=True)
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install ElasticSearch: ')
        traceback.print_exc(file=sys.stderr)
        return False
    if stdout:
        sys.stdout.write('[+] *** ElasticSearch installed successfully. ***\n\n')
        sys.stdout.write('[+] Next, Start your cluster: \'dynamite start elasticsearch\'.\n')
    sys.stdout.flush()
    return ElasticProfiler(stderr=False).is_installed


def uninstall_elasticsearch(stdout=False, prompt_user=True):
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
