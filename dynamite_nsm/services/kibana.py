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
    from urllib.parse import urlencode

from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.package_manager import OSPackageManager
from dynamite_nsm.services.elasticsearch import ElasticProcess
from dynamite_nsm.services.elasticsearch import ElasticProfiler

INSTALL_DIRECTORY = '/opt/dynamite/kibana/'
CONFIGURATION_DIRECTORY = '/etc/dynamite/kibana/'
LOG_DIRECTORY = '/var/log/dynamite/kibana/'


class KibanaAPIConfigurator:
    """
    Provides an interface for interacting with the Kibana APIs
    """
    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):

        self.configuration_directory = configuration_directory
        self.kibana_config = KibanaConfigurator(configuration_directory)

    def create_elastiflow_saved_objects(self, stdout=False):
        """
        Creates ElastiFlow dashboards, visualizations, and searches

        :param stdout: Print output to console
        :return: True, if created successfully
        """

        kibana_api_objects_path = os.path.join(const.INSTALL_CACHE, const.DEFAULT_CONFIGS, 'kibana', 'objects',
                                               'saved_objects.ndjson')

        server_host = self.kibana_config.server_host
        if server_host.strip() == '0.0.0.0':
            server_host = 'localhost'

        # This isn't ideal, but given there is no easy way to use the urllib/urllib2 libraries for multipart/form-data
        # Shelling out is a reasonable workaround
        kibana_api_import_url = '{}:{}/api/saved_objects/_import'.format(server_host,
                    self.kibana_config.server_port)
        curl_command = 'curl -X POST {} -u {}:"{}" --form file=@{} -H "kbn-xsrf: true" ' \
                       '-H "Content-Type: multipart/form-data" -v'.format(
            kibana_api_import_url, self.kibana_config.elasticsearch_username, self.kibana_config.elasticsearch_password,
            kibana_api_objects_path
        )
        p = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        out, err = p.communicate()
        out, err = out.decode('utf-8'), err.decode('utf-8')
        if "HTTP/1.1 200" in err or "HTTP/1.1 409" in err:
            if stdout:
                sys.stdout.write('[+] Successfully created ElastiFlow Objects.\n')
            return True
        else:
            sys.stderr.write('[-] Failed to create ElastiFlow objects - [{}]\n'.format(err))
        return False


class KibanaConfigurator:

    tokens = {
        'server_host': ('server.host',),
        'server_port': ('server.port', ),
        'elasticsearch_hosts': ('elasticsearch.hosts',),
        'elasticsearch_username': ('elasticsearch.username',),
        'elasticsearch_password': ('elasticsearch.password',),
    }

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        self.configuration_directory = configuration_directory
        self.kibana_home = None
        self.kibana_path_conf = None
        self.kibana_logs = None
        self.server_host = None
        self.server_port = None
        self.elasticsearch_hosts = None
        self.elasticsearch_username = None
        self.elasticsearch_password = None
        self._parse_environment_file()
        self._parse_kibanayaml()

    def _parse_kibanayaml(self):

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

        with open(os.path.join(self.configuration_directory, 'kibana.yml'), 'r') as configyaml:
            self.config_data = load(configyaml, Loader=Loader)

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def _parse_environment_file(self):
        """
        Parses the /etc/dynamite/environment file and returns results for JAVA_HOME, KIBANA_PATH_CONF, KIBANA_HOME;
        KIBANA_LOGS

        stores the results in class variables of the same name
        """
        for line in open('/etc/dynamite/environment').readlines():
            if line.startswith('JAVA_HOME'):
                self.java_home = line.split('=')[1].strip()
            elif line.startswith('KIBANA_PATH_CONF'):
                self.kibana_path_conf = line.split('=')[1].strip()
            elif line.startswith('KIBANA_HOME'):
                self.kibana_home = line.split('=')[1].strip()
            elif line.startswith('KIBANA_LOGS'):
                self.kibana_logs = line.split('=')[1].strip()

    def write_config(self):

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
        filebeat_config_backup = os.path.join(backup_configurations, 'kibana.yaml.backup.{}'.format(timestamp))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.copy(os.path.join(self.configuration_directory, 'kibana.yml'), filebeat_config_backup)

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        with open(os.path.join(self.configuration_directory, 'kibana.yml'), 'w') as configyaml:
            dump(self.config_data, configyaml, default_flow_style=False)


class KibanaInstaller:
    """
    Provides a simple interface for installing a new Kibana interface with ElastiFlow dashboards
    """
    def __init__(self,
                 host='0.0.0.0',
                 port=5601,
                 elasticsearch_host=None,
                 elasticsearch_port=None,
                 elasticsearch_password='changeme',
                 install_directory=INSTALL_DIRECTORY,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 log_directory=LOG_DIRECTORY,
                 download_kibana_archive=True,
                 stdout=True,
                 verbose=False):
        """
        :param host: The IP address to listen on (E.G "0.0.0.0")
        :param port: The port that the Kibana UI/API is bound to (E.G 5601)
        :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
        :param elasticsearch_port: A port number for the target elasticsearch instance
        :param elasticsearch_password: The password used for authentication across all builtin ES users
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/kibana/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/kibana/)
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
            if ElasticProfiler().is_installed:
                self.elasticsearch_host = 'localhost'
            else:
                raise Exception("ElasticSearch must either be installed locally, or a remote host must be specified.")
        self.install_directory = install_directory
        self.configuration_directory = configuration_directory
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose
        if download_kibana_archive:
            self.download_kibana()
            self.extract_kibana()

    def _create_kibana_directories(self):
        if self.stdout:
            sys.stdout.write('[+] Creating kibana install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.install_directory, 'data')), shell=True)

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
        for path in config_paths:
            if self.stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                    self.configuration_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                            self.configuration_directory)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            if self.stdout:
                sys.stdout.write('[+] Copying {} -> {}\n'.format(
                    os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                    self.install_directory))
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                            self.install_directory)
            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))

    def _create_kibana_environment_variables(self):
        if 'KIBANA_PATH_CONF' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating Kibana default configuration path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo KIBANA_PATH_CONF="{}" >> /etc/dynamite/environment'.format(
                self.configuration_directory),
                            shell=True)
        if 'KIBANA_HOME' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating Kibana default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo KIBANA_HOME="{}" >> /etc/dynamite/environment'.format(self.install_directory),
                            shell=True)
        if 'KIBANA_LOGS' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating Kibana default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo KIBANA_LOGS="{}" >> /etc/dynamite/environment'.format(self.log_directory),
                            shell=True)

    def _install_kibana_objects(self):
        if KibanaProfiler().is_installed and (ElasticProfiler().is_installed or self.elasticsearch_host != 'localhost'):
            if self.stdout:
                sys.stdout.write('[+] Installing Kibana Dashboards\n')
            if self.stdout:
                sys.stdout.write('[+] Waiting for ElasticSearch to become accessible.\n')
            # Start ElasticSearch if it is installed locally and is not running
            if self.elasticsearch_host in ['localhost', '127.0.0.1', '0.0.0.0', '::1', '::/128']:
                sys.stdout.write('[+] Starting ElasticSearch.\n')
                ElasticProcess().start(stdout=self.stdout)
                sys.stdout.flush()
                while not ElasticProfiler().is_listening:
                    if self.stdout:
                        sys.stdout.write('[+] Waiting for ElasticSearch API to become accessible.\n')
                    time.sleep(5)
                if self.stdout:
                    sys.stdout.write('[+] ElasticSearch API is up.\n')
                    sys.stdout.write('[+] Sleeping for 10 seconds, while ElasticSearch API finishes booting.\n')
                    sys.stdout.flush()
                time.sleep(10)
            kibana_process = KibanaProcess()
            kibana_process.optimize(stdout=self.stdout)
            utilities.set_ownership_of_file('/opt/dynamite/', user='dynamite', group='dynamite')
            utilities.set_ownership_of_file('/etc/dynamite/', user='dynamite', group='dynamite')
            time.sleep(5)
            sys.stdout.write('[+] Starting Kibana.\n')
            kibana_process.start(stdout=self.stdout)
            while not KibanaProfiler().is_listening:
                if self.stdout:
                    sys.stdout.write('[+] Waiting for Kibana API to become accessible.\n')
                time.sleep(5)
            if self.stdout:
                sys.stdout.write('[+] Kibana API is up.\n')
                sys.stdout.write('[+] Sleeping for 15 seconds, while Kibana API finishes booting.\n')
                sys.stdout.flush()
            time.sleep(15)
            api_config = KibanaAPIConfigurator(self.configuration_directory)
            kibana_object_create_attempts = 1
            while not api_config.create_elastiflow_saved_objects():
                if self.stdout:
                    sys.stdout.write('[+] Attempting to dashboards/visualizations [Attempt {}]\n'.format(
                        kibana_object_create_attempts))
                kibana_object_create_attempts += 1
                time.sleep(10)
            if self.stdout:
                sys.stdout.write('[+] Successfully created dashboards/visualizations.\n')
            kibana_process.stop()

    def _setup_default_kibana_configs(self):
        if self.stdout:
            sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'kibana', 'kibana.yml'),
                    self.configuration_directory)
        local_config = KibanaConfigurator(self.configuration_directory)
        local_config.elasticsearch_hosts = ['http://{}:{}'.format(self.elasticsearch_host,
                                                                    self.elasticsearch_port)]
        local_config.server_host = self.host
        local_config.server_port = self.port
        local_config.elasticsearch_password = self.elasticsearch_password
        local_config.elasticsearch_username = 'elastic'
        local_config.write_config()

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

    def setup_kibana(self):
        """
        Create required directories, files, and variables to run ElasticSearch successfully;
        """
        pacman = OSPackageManager(verbose=self.verbose)
        pacman.refresh_package_indexes()
        pacman.install_packages(['curl'])
        self._create_kibana_directories()
        self._copy_kibana_files_and_directories()
        self._create_kibana_environment_variables()
        self._setup_default_kibana_configs()
        self._install_kibana_objects()
        utilities.set_ownership_of_file('/etc/dynamite/', user='dynamite', group='dynamite')
        utilities.set_ownership_of_file('/opt/dynamite/', user='dynamite', group='dynamite')
        utilities.set_ownership_of_file('/var/log/dynamite', user='dynamite', group='dynamite')


class KibanaProfiler:
    """
    Interface for determining whether Kibana is installed/configured/running properly.
    """
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
                sys.stderr.write('[-] Kibana installation directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(kibana_home):
            if stderr:
                sys.stderr.write('[-] Kibana installation directory could not be located at {}.\n'.format(
                    kibana_home))
            return False
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
        if not utilities.check_user_exists('dynamite'):
            sys.stderr.write('[-] dynamite user was not created.\n')
            return False
        return True

    @staticmethod
    def _is_configured(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        kibana_path_conf = env_dict.get('KIBANA_PATH_CONF')
        if not kibana_path_conf:
            if stderr:
                sys.stderr.write('[-] Kibana configuration directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(os.path.join(kibana_path_conf, 'kibana.yml')):
            if stderr:
                sys.stderr.write('[-] Could not locate kibana.yml in {}\n'.format(kibana_path_conf))
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
        try:
            return KibanaProcess().status()['RUNNING']
        except Exception:
            return False

    @staticmethod
    def _is_listening(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        kibana_path_conf = env_dict.get('KIBANA_PATH_CONF')
        if not kibana_path_conf:
            if stderr:
                sys.stderr.write('[-] Kibana configuration directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(os.path.join(kibana_path_conf, 'kibana.yml')):
            if stderr:
                sys.stderr.write('[-] Could not locate kibana.yml in {}\n'.format(kibana_path_conf))
            return False
        try:
            kibana_config = KibanaConfigurator(configuration_directory=kibana_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable elasticsearch.yml or jvm.options \n')
            return False
        host = kibana_config.server_host
        port = kibana_config.server_port
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


class KibanaProcess:
    """
    An interface for start|stop|status|restart of the Kibana process
    """
    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('KIBANA_PATH_CONF')
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

            # We use su instead of runuser here because of nodes' weird dependency on PAM
            # when calling from within a sub-shell
            subprocess.call('su -l dynamite -c "{}/bin/kibana -c {} -l {} & > /dev/null &"'.format(
                                    self.config.kibana_home,
                                    os.path.join(self.config.kibana_path_conf, 'kibana.yml'),
                                    os.path.join(self.config.kibana_logs, 'kibana.log')
                                ), shell=True, env=utilities.get_environment_file_dict())

        if not os.path.exists('/var/run/dynamite/kibana/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/kibana/'), shell=True)
        utilities.set_ownership_of_file('/var/run/dynamite', user='dynamite', group='dynamite')

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
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)
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

    def optimize(self, stdout=False):
        if not os.path.exists('/var/run/dynamite/kibana/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/kibana/'), shell=True)
        utilities.set_ownership_of_file('/var/run/dynamite', user='dynamite', group='dynamite')
        if stdout:
            sys.stdout.write('[+] Optimizing Kibana Libraries.\n')

        # Kibana initially has to be called as root due to a process forking issue when using runuser
        # builtin
        subprocess.call('{}/bin/kibana --optimize --allow-root'.format(
            self.config.kibana_home,
        ), shell=True, env=utilities.get_environment_file_dict())
        # Pass permissions back to dynamite user
        utilities.set_ownership_of_file('/var/log/dynamite', user='dynamite', group='dynamite')


def change_kibana_elasticsearch_password(password='changeme', prompt_user=True, stdout=False):
    if prompt_user:
        resp = utilities.prompt_input(
            'Changing the Kibana password can cause Kibana to lose communication with ElasticSearch. '
            'Are you sure you wish to continue? [no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    kb_config = KibanaConfigurator(configuration_directory=CONFIGURATION_DIRECTORY)
    kb_config.elasticsearch_password = password
    kb_config.write_config()
    return KibanaProcess().restart(stdout=True)


def install_kibana(elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme',
                   install_jdk=True, create_dynamite_user=True, stdout=False, verbose=False):
    """
    Install Kibana/ElastiFlow Dashboards

    :param elasticsearch_host: [Optional] A hostname/IP of the target elasticsearch instance
    :param elasticsearch_port: [Optional] A port number for the target elasticsearch instance
    :param elasticsearch_password: The password used for authentication across all builtin ES users
    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run
    Logstash/ElasticSearch/Kibana
    :param stdout: Print the output to console
    :param verbose: Include output from system utilities
    :return: True, if installation succeeded
    """
    kb_profiler = KibanaProfiler()
    if kb_profiler.is_installed:
        sys.stderr.write('[-] Kibana is already installed. If you wish to re-install, first uninstall.\n')
        return False
    if utilities.get_memory_available_bytes() < 2 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite Kibana requires at-least 2GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes()/(1000 ** 3)
        ))
        return False
    try:
        kb_installer = KibanaInstaller(elasticsearch_host=elasticsearch_host,
                                       elasticsearch_port=elasticsearch_port,
                                       elasticsearch_password=elasticsearch_password,
                                       download_kibana_archive=not kb_profiler.is_downloaded,
                                       stdout=stdout, verbose=verbose)
        if install_jdk:
            utilities.download_java(stdout=stdout)
            utilities.extract_java(stdout=stdout)
            utilities.setup_java()
        if create_dynamite_user:
            utilities.create_dynamite_user(utilities.generate_random_password(50))
        kb_installer.setup_kibana()
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install Kibana: ')
        traceback.print_exc(file=sys.stderr)
        return False
    if stdout:
        sys.stdout.write('[+] *** Kibana + Dashboards installed successfully. ***\n\n')
        sys.stdout.write('[+] Next, Start your collector: \'dynamite start kibana\'.\n')
        sys.stdout.flush()
    return KibanaProfiler(stderr=False).is_installed


def uninstall_kibana(stdout=False, prompt_user=True):
    """
    Uninstall Kibana/ElastiFlow Dashboards

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    :return: True, if uninstall succeeded
    """
    kb_profiler = KibanaProfiler()
    kb_config = KibanaConfigurator(configuration_directory=CONFIGURATION_DIRECTORY)
    if not kb_profiler.is_installed:
        sys.stderr.write('[-] Kibana is not installed.\n')
        return False
    if prompt_user:
        sys.stderr.write('[-] WARNING! REMOVING KIBANA WILL PREVENT YOU FROM VIEWING NETWORK EVENTS.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    if kb_profiler.is_running:
        KibanaProcess().stop(stdout=stdout)
    try:
        shutil.rmtree(kb_config.kibana_path_conf)
        shutil.rmtree(kb_config.kibana_home)
        shutil.rmtree(kb_config.kibana_logs)
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        env_lines = ''
        for line in open('/etc/dynamite/environment').readlines():
            if 'KIBANA_PATH_CONF' in line:
                continue
            elif 'KIBANA_HOME' in line:
                continue
            elif 'KIBANA_LOGS' in line:
                continue
            elif line.strip() == '':
                continue
            env_lines += line.strip() + '\n'
        open('/etc/dynamite/environment', 'w').write(env_lines)
        if stdout:
            sys.stdout.write('[+] Kibana uninstalled successfully.\n')
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to uninstall Kibana: ')
        traceback.print_exc(file=sys.stderr)
        return False
    return True
