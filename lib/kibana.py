import os
import sys
import time
import json
import shutil
import signal
import tarfile
import traceback
import subprocess

from multiprocessing import Process

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

from lib import const
from lib import utilities
from lib.logstash import LogstashProfiler
from lib.elastiflow import ElastiFlowInstaller

INSTALL_DIRECTORY = '/opt/dynamite/kibana/'
CONFIGURATION_DIRECTORY = '/etc/dynamite/kibana/'
LOG_DIRECTORY = '/var/log/dynamite/kibana/'


class KibanaAPIConfigurator:

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        self.configuration_directory = configuration_directory
        self.kibana_config = KibanaConfigurator(configuration_directory)
        es_flow_installer = ElastiFlowInstaller()
        if not LogstashProfiler().is_elastiflow_downloaded:
            es_flow_installer.download_elasticflow()
            es_flow_installer.extract_elastiflow()
        es_flow_installer.extract_elastiflow()

    def create_elastiflow_dashboards(self, stdout=False):

        def chunks(l, n):
            """Yield successive n-sized chunks from l."""
            for i in range(0, len(l), n):
                yield l[i:i + n]

        with open(os.path.join(const.INSTALL_CACHE, const.ELASTIFLOW_DIRECTORY_NAME, 'kibana',
                               const.ELASTIFLOW_DASHBOARDS_CONFIG)) as kibana_dashboards_obj:
            kibana_objects = json.loads(kibana_dashboards_obj.read())
            for i, k_objects in enumerate(chunks(kibana_objects, len(kibana_objects)/4)):
                try:
                    url_request = Request(
                        url='http://{}:{}/api/kibana/dashboards/import'.format(
                            self.kibana_config.get_server_host(),
                            self.kibana_config.get_server_port()
                        ),
                        data=json.dumps(kibana_objects),
                        headers={'Content-Type': 'application/json', 'kbn-xsrf': True}
                    )
                    response = urlopen(url_request)
                except HTTPError as e:
                    sys.stderr.write('[-] Failed to create dashboards - [{}]\n'.format(e))
                    return False
                except URLError as e:
                    sys.stderr.write('[-] Failed to create dashboards - [{}]\n'.format(e))
                    return False
                if stdout:
                    sys.stdout.write('[+] Successfully created ElastiFlow Objects [Set: {}]. [API_RESPONSE: {}]\n'.format((i+1), response.read()))
            return True

    def create_elastiflow_index_patterns(self, stdout=False):
        with open(os.path.join(const.INSTALL_CACHE, const.ELASTIFLOW_DIRECTORY_NAME, 'kibana',
                               const.ELASTIFLOW_INDEX_PATTERNS)) as kibana_patterns_obj:
            try:
                url_request = Request(
                    url='http://{}:{}/api/saved_objects/index-pattern/elastiflow-*'.format(
                        self.kibana_config.get_server_host(),
                        self.kibana_config.get_server_port()
                    ),
                    data=kibana_patterns_obj.read(),
                    headers={'Content-Type': 'application/json', 'kbn-xsrf': True}
                )
                response = urlopen(url_request)
            except HTTPError as e:
                sys.stderr.write('[-] Failed to create index-patterns - [{}]\n'.format(e))
                return False
            except URLError as e:
                sys.stderr.write('[-] Failed to create index-patterns - [{}]\n'.format(e))
                return False
            if stdout:
                sys.stdout.write('[+] Successfully created index-patterns. [API_RESPONSE: {}]\n'.format(
                    response.read()))
            return True


class KibanaConfigurator:

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        self.configuration_directory = configuration_directory
        self.kb_config_options = self._parse_kibanayaml()
        self.kibana_home = None
        self.kibana_path_conf = None
        self.kibana_logs = None
        self._parse_environment_file()

    def _parse_kibanayaml(self):
        """
        Parse kibana.yml, return a object representing the config
        :return: A dictionary of config options and their values
        """
        kb_config_options = {}
        for line in open(os.path.join(self.configuration_directory, 'kibana.yml')).readlines():
            if not line.startswith('#') and ':' in line:
                if line.startswith('elasticsearch.hosts:'):
                    k = 'elasticsearch.hosts'
                    v = json.loads(line.replace('elasticsearch.hosts:', '').strip())
                else:
                    k, v = line.strip().split(':')
                kb_config_options[k] = str(v).strip().replace('"','').replace("'",'')
        return kb_config_options

    def _parse_environment_file(self):
        """
        Parses the /etc/environment file and returns results for JAVA_HOME, KIBANA_PATH_CONF, KIBANA_HOME; KIBANA_LOGS
        stores the results in class variables of the same name
        """
        for line in open('/etc/environment').readlines():
            if line.startswith('JAVA_HOME'):
                self.java_home = line.split('=')[1].strip()
            elif line.startswith('KIBANA_PATH_CONF'):
                self.kibana_path_conf = line.split('=')[1].strip()
            elif line.startswith('KIBANA_HOME'):
                self.kibana_home = line.split('=')[1].strip()
            elif line.startswith('KIBANA_LOGS'):
                self.kibana_logs = line.split('=')[1].strip()

    def get_server_host(self):
        """
        :return: The host the Kibana is running on
        """
        return self.kb_config_options['server.host']

    def get_server_port(self):
        """
        :return: The port the Kibana is running on
        """
        return self.kb_config_options['server.port']

    def get_elasticsearch_hosts(self):
        """
        :return: A list of elasticsearch hosts to connect too
        """
        return self.kb_config_options['elasticsearch.hosts']

    def set_server_host(self, host='0.0.0.0'):
        """
        :param host: The IP address for Kibana service to listen on
        """
        self.kb_config_options['server.host'] = host

    def set_server_port(self, port=5601):
        """
        :param port: The port number of the for Kibana service to listen on
        """
        self.kb_config_options['server.port'] = str(port)

    def set_elasticsearch_hosts(self, host_list):
        """
        :param host_list: A list of ElasticSearch hosts for Kibana to connect too
        """
        self.kb_config_options['elasticsearch.hosts'] = json.dumps(host_list)

    def write_configs(self):
        """
        Write (and backs-up) kibana.yml configuration
        """
        timestamp = int(time.time())
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        kibana_config_backup = os.path.join(backup_configurations, 'kibana.yml.backup.{}'.format(timestamp))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.move(os.path.join(self.configuration_directory, 'kibana.yml'), kibana_config_backup)
        with open(os.path.join(self.configuration_directory, 'kibana.yml'), 'a') as kibana_search_config_obj:
            for k, v in self.kb_config_options.items():
                kibana_search_config_obj.write('{}: {}\n'.format(k, v))


class KibanaInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 log_directory=LOG_DIRECTORY):
        self.install_directory = install_directory
        self.configuration_directory = configuration_directory
        self.log_directory = log_directory

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

    def setup_kibana(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating kibana install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.install_directory, 'data')), shell=True)
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
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                            self.configuration_directory)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                            self.install_directory)
            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        if 'KIBANA_PATH_CONF' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Kibana default configuration path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo KIBANA_PATH_CONF="{}" >> /etc/environment'.format(self.configuration_directory),
                            shell=True)
        if 'KIBANA_HOME' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Kibana default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo KIBANA_HOME="{}" >> /etc/environment'.format(self.install_directory),
                            shell=True)
        if 'KIBANA_LOGS' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Kibana default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo KIBANA_LOGS="{}" >> /etc/environment'.format(self.log_directory),
                            shell=True)
        if stdout:
            sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'kibana', 'kibana.yml'),
                    self.configuration_directory)

        utilities.set_ownership_of_file('/etc/dynamite/')
        utilities.set_ownership_of_file('/opt/dynamite/')
        utilities.set_ownership_of_file('/var/log/dynamite')
        if KibanaProfiler().is_installed:
            if stdout:
                sys.stdout.write('[+] Installing Kibana Dashboards\n')
            KibanaProcess(self.configuration_directory).start()
            if stdout:
                sys.stdout.write('[+] Waiting for Kibana API to become accessible.\n')
            while not KibanaProfiler().is_listening:
                if stdout:
                    sys.stdout.write('[+] Waiting for Kibana API to become accessible.\n')
                time.sleep(5)
            if stdout:
                sys.stdout.write('[+] Kibana API is up, creating dashboards.\n')
            time.sleep(10)
            api_config = KibanaAPIConfigurator(self.configuration_directory)
            api_config.create_elastiflow_index_patterns(stdout=stdout)
            api_config.create_elastiflow_dashboards(stdout=stdout)
            time.sleep(2)
            # KibanaProcess(self.configuration_directory).stop()


class KibanaProfiler:

    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_configured = self._is_configured(stderr=stderr)
        self.is_running = self._is_running()
        self.is_listening = self._is_listening(stderr=stderr)

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.KIBANA_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] Kibana installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        kibana_home = env_dict.get('KIBANA_HOME')
        if not kibana_home:
            if stderr:
                sys.stderr.write('[-] Kibana installation directory could not be located in /etc/environment.\n')
        kibana_home_files_and_dirs = os.listdir(kibana_home)
        if 'bin' not in kibana_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate Kibana {}/bin directory.\n'.format(kibana_home))
            return False
        if 'webpackShims' not in kibana_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate Kibana {}/webpackShims directory.\n'.format(kibana_home))
            return False
        kibana_binaries = os.listdir(os.path.join(kibana_home, 'bin'))
        if 'kibana' not in kibana_binaries:
            if stderr:
                sys.stderr.write('[-] Could not locate Kibana binary in {}/bin/\n'.format(kibana_home))
            return False
        return True

    @staticmethod
    def _is_configured(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        kibana_path_conf = env_dict.get('KIBANA_PATH_CONF')
        if not os.path.exists(os.path.join(kibana_path_conf, 'kibana.yml')):
            if stderr:
                sys.stderr.write('[-] Could not locate kibana.yml in {}'.format(kibana_path_conf))
            return False
        try:
            KibanaConfigurator(configuration_directory=kibana_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable kibana.yml \n')
            return False
        return True

    @staticmethod
    def _is_running():
        return KibanaProcess().status()['RUNNING']

    @staticmethod
    def _is_listening(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        kibana_path_conf = env_dict.get('KIBANA_PATH_CONF')
        if not os.path.exists(os.path.join(kibana_path_conf, 'kibana.yml')):
            if stderr:
                sys.stderr.write('[-] Could not locate kibana.yml in {}'.format(kibana_path_conf))
            return False
        try:
            kibana_config = KibanaConfigurator(configuration_directory=kibana_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable elasticsearch.yml or jvm.options \n')
            return False
        host = kibana_config.get_server_host()
        port = kibana_config.get_server_port()
        if host.strip() == '0.0.0.0':
            host = 'localhost'
        return utilities.check_socket(host, port)


class KibanaProcess:
    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
        """

        self.configuration_directory = configuration_directory
        self.config = KibanaConfigurator(self.configuration_directory)
        try:
            self.pid = int(open('/var/run/dynamite/kibana/kibana.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the Kibana process
        :param stdout: Print output to console
        :return: True, if started successfully
        """
        def start_shell_out():
            subprocess.call('runuser -l dynamite -c "{} {}/bin/kibana '
                            '-c {} -l {} &>/dev/null &"'.format(
                                utilities.get_environment_file_str(),
                                self.config.kibana_home,
                                os.path.join(self.config.kibana_path_conf, 'kibana.yml'),
                                os.path.join(self.config.kibana_logs, 'kibana.log')
                            ), shell=True)
        if not os.path.exists('/var/run/dynamite/kibana/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/kibana/'), shell=True)
            utilities.set_ownership_of_file('/var/run/dynamite')

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] Kibana is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting Kibana on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/kibana/kibana.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting Kibana on PID [{}]\n'.format(retry + 1, self.pid)
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
        Stop the Kibana process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop Kibana [{}]\n'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGKILL
                else:
                    # Kill the zombie after the third attempt of asking it to kill itself
                    sig_command = signal.SIGTERM
                attempts += 1
                os.kill(self.pid, sig_command)
                time.sleep(1)

                alive = utilities.check_pid(self.pid)
            except Exception as e:
                sys.stderr.write('[-] An error occurred while attempting to stop Kibana: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the Kibana process

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
        log_path = os.path.join(self.config.kibana_logs, 'kibana.log')

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'USER': 'dynamite',
            'LOGS': log_path
        }


def install_kibana(install_jdk=True, create_dynamite_user=True, stdout=False):
    """
    Install Kibana/ElastiFlow Dashboards

    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run
    Logstash/ElasticSearch/Kibana
    :param stdout: Print the output to console
    :return: True, if installation succeeded
    """
    if utilities.get_memory_available_bytes() < 3 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite Kibana requires at-least 3GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes()/(1024 ** 3)
        ))
        return False
    try:
        kb_installer = KibanaInstaller()
        if install_jdk:
            utilities.download_java(stdout=True)
            utilities.extract_java(stdout=True)
            utilities.setup_java()
        if create_dynamite_user:
            utilities.create_dynamite_user('password')
        kb_installer.download_kibana(stdout=True)
        kb_installer.extract_kibana(stdout=True)
        kb_installer.setup_kibana(stdout=True)
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install Kibana: ')
        traceback.print_exc(file=sys.stderr)
        return False
    if stdout:
        sys.stdout.write('[+] *** Kibana + Dashboards installed successfully. ***\n\n')
        sys.stdout.write('[+] Next, Start your collector: \'dynamite.py start kibana\'.\n')
        sys.stdout.flush()
    return True