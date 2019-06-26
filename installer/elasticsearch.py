import os
import sys
import crypt
import shutil
import getpass
import tarfile
import subprocess

from datetime import datetime

try:
    from urllib2 import urlopen
    from urllib2 import URLError
except Exception:
    from urllib.request import urlopen
    from urllib.error import URLError

ELASTICSEARCH_ARCHIVE_NAME = 'elasticsearch-7.1.1.tar.gz'
JAVA_ARCHIVE_NAME = 'java-11.0.2.tar.gz'
INSTALL_CACHE = os.environ['DYNAMITE_INSTALL_CACHE']
DEFAULT_CONFIGS = os.environ['DEFAULT_CONFIGS']
ELASTICSEARCH_MIRRORS = os.environ['ELASTICSEARCH_LINUX_MIRRORS']
JAVA_MIRRORS = os.environ['JAVA_LINUX_MIRRORS']


def is_root():
    return getpass.getuser() == 'root'


def create_dynamite_user(password):
    pass_encry = crypt.crypt(password)
    subprocess.call('useradd -p "{}" -s /bin/bash dynamite'.format(pass_encry), shell=True)


def download_file(url, filename, stdout=False):
    """
    :param url: The url to the file to download
    :param filename: The name of the file to store
    :return: None
    """
    response = urlopen(url)
    CHUNK = 16 * 1024
    if stdout:
        sys.stdout.write('Downloading: {} \t|\t Filename: {}\n'.format(url, filename))
        sys.stdout.write('Progress: ')
        sys.stdout.flush()
    try:
        with open(os.path.join(INSTALL_CACHE, filename), 'wb') as f:
            chunk_num = 0
            while True:
                chunk = response.read(CHUNK)
                if stdout:
                    if chunk_num % 100 == 0:
                        sys.stdout.write('+')
                        sys.stdout.flush()
                if not chunk:
                    break
                chunk_num += 1
                f.write(chunk)
            if stdout:
                sys.stdout.write('\nComplete! [{} bytes written]\n'.format((chunk_num + 1) * CHUNK))
                sys.stdout.flush()
    except URLError as e:
        sys.stderr.write('An error occurred while attempting to download file. [{}]'.format(e))
        return False
    return True


def set_ownership_of_file(path):
    for root, dirs, files in os.walk(path):
        for momo in dirs:
            shutil.chown(os.path.join(root, momo), user='dynamite', group='dynamite')
        for momo in files:
            shutil.chown(os.path.join(root, momo), user='dynamite', group='dynamite')


class ElasticConfigurator:

    def __init__(self, config_directory):
        self.config_directory = config_directory
        self.es_config_options = self._parse_elasticyaml()
        self.jvm_config_options = self._parse_jvm_options()

    def _parse_elasticyaml(self):
        es_config_options = {}
        for line in open(os.path.join(self.config_directory, 'elasticsearch.yml')).readlines():
            if not line.startswith('#'):
                print(line)
                k, v = line.strip().split(':')
                es_config_options[k] = v
        return es_config_options

    def _parse_jvm_options(self):
        jvm_options = {}
        for line in open(os.path.join(self.config_directory, 'jvm.options')).readlines():
            if not line.startswith('#') and '-Xms' in line:
                jvm_options['initial_memory'] = line.replace('-Xms', '').strip()
            elif not line.startswith('#') and '-Xmx' in line:
                jvm_options['maximum_memory'] = line.replace('-Xmx', '').strip()
        return jvm_options

    def _overwrite_jvm_options(self):
        new_output = ''
        for line in open(os.path.join(self.config_directory, 'jvm.options')).readlines():
            if not line.startswith('#') and '-Xms' in line:
                new_output += '-Xms' + self.jvm_config_options['initial_memory']
            elif not line.startswith('#') and '-Xmx' in line:
                new_output += '-Xmx' + self.jvm_config_options['maximum_memory']
            else:
                new_output += line
            new_output += '\n'
        open(os.path.join(self.config_directory, 'jvm.options'), 'w').write(new_output)

    def get_cluster_name(self):
        return self.es_config_options.get('cluster.name')

    def get_network_host(self):
        return self.es_config_options.get('network.host')

    def get_network_port(self):
        return self.es_config_options.get('http.port')

    def get_data_path(self):
        return self.es_config_options.get('path.data')

    def get_log_path(self):
        return self.es_config_options.get('path.logs')

    def set_cluster_name(self, name):
        self.es_config_options['cluster.name'] = name

    def set_network_host(self, host):
        self.es_config_options['network.host'] = host

    def set_network_port(self, port):
        self.es_config_options['http.port'] = port

    def set_node_name(self, name):
        self.es_config_options['node.name'] = name

    def set_data_path(self, path):
        self.es_config_options['path.data'] = path

    def set_log_path(self, path):
        self.es_config_options['path.logs'] = path

    def set_discovery_seed_host(self, host_list):
        self.es_config_options['discovery.seed_hosts'] = host_list

    def write_configs(self):
        backup_configurations = os.path.join(self.config_directory, 'config_backups/')
        es_config_backup = os.path.join(backup_configurations, 'elasticsearch.yml.backup.{}'.format(
            datetime.utcnow().timestamp()))
        java_config_backup = os.path.join(backup_configurations, 'java.options.backup.{}'.format(
            datetime.utcnow().timestamp()
        ))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.move(os.path.join(self.config_directory, 'elasticsearch.yml'), es_config_backup)
        shutil.copy(os.path.join(self.config_directory, 'jvm.options'), java_config_backup)
        with open(os.path.join(self.config_directory, 'elasticsearch.yml'), 'a') as elastic_search_config_obj:
            for k, v in self.es_config_options.items():
                elastic_search_config_obj.write('{}: {}\n'.format(k, v))
        self._overwrite_jvm_options()


class ElasticInstaller:
    CONFIGURATION_DIRECTORY = '/etc/dynamite/elasticsearch/'
    INSTALL_DIRECTORY = '/opt/dynamite/elasticsearch/'
    LOG_DIRECTORY = '/var/log/dynamite/elasticsearch/'

    def __init__(self):
        self.elasticsearch_downloaded = False
        self.elasticsearch_extracted = False
        self.java_downloaded = False
        self.java_extracted = False

    def download_elasticsearch(self, stdout=False):
        for url in open(ELASTICSEARCH_MIRRORS, 'r').readlines():
            if download_file(url, ELASTICSEARCH_ARCHIVE_NAME, stdout):
                self.elasticsearch_downloaded = True
                break

    def download_java(self, stdout=False):
        for url in open(JAVA_MIRRORS, 'r').readlines():
            if download_file(url, JAVA_ARCHIVE_NAME, stdout):
                self.java_downloaded = True
                break

    def extract_elasticsearch(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(ELASTICSEARCH_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(INSTALL_CACHE, ELASTICSEARCH_ARCHIVE_NAME))
            tf.extractall(path=INSTALL_CACHE)
            sys.stdout.write('Complete!')
            sys.stdout.flush()
            self.elasticsearch_extracted = True
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def extract_java(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(JAVA_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(INSTALL_CACHE, JAVA_ARCHIVE_NAME))
            tf.extractall(path=INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
            self.java_extracted = True
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_elasticsearch(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating dynamite install/configuration/logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.INSTALL_DIRECTORY), shell=True)
        subprocess.call('mkdir -p {}'.format(self.CONFIGURATION_DIRECTORY), shell=True)
        subprocess.call('mkdir -p {}'.format(self.LOG_DIRECTORY), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.INSTALL_DIRECTORY, 'data')), shell=True)
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
            try:
                shutil.move(os.path.join(INSTALL_CACHE, 'elasticsearch-7.1.1/{}'.format(path)),
                            self.CONFIGURATION_DIRECTORY)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            try:
                shutil.move(os.path.join(INSTALL_CACHE, 'elasticsearch-7.1.1/{}'.format(path)),
                            self.INSTALL_DIRECTORY)
            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        if 'ES_PATH_CONF' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[-] Updating ElasticSearch default configuration path [{}]\n'.format(self.CONFIGURATION_DIRECTORY))
            subprocess.call('echo ES_PATH_CONF="{}" >> /etc/environment'.format(self.CONFIGURATION_DIRECTORY),
                            shell=True)
        subprocess.call('source /etc/environment', shell=True)
        sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(DEFAULT_CONFIGS, 'elasticsearch', 'elasticsearch.yml'), self.CONFIGURATION_DIRECTORY)
        set_ownership_of_file(self.CONFIGURATION_DIRECTORY)
        set_ownership_of_file(self.INSTALL_DIRECTORY)
        set_ownership_of_file(self.LOG_DIRECTORY)

    def setup_java(self):
        subprocess.call('mkdir -p /usr/lib/jvm', shell=True)
        try:
            shutil.move(os.path.join(INSTALL_CACHE, 'jdk-11.0.2'), '/usr/lib/jvm/')
        except shutil.Error as e:
            sys.stderr.write('[-] JVM already exists at path specified. [{}]\n'.format(e))
        try:
            os.symlink('/usr/lib/jvm/jdk-11.0.2/bin/java', '/usr/bin/java')
        except Exception as e:
            sys.stderr.write('[-] Java Sym-link already exists at path specified. [{}]\n'.format(e))
        if 'JAVA_HOME' not in open('/etc/environment').read():
            subprocess.call('echo JAVA_HOME="/usr/lib/jvm/jdk-11.0.2/" >> /etc/environment', shell=True)
        subprocess.call('source /etc/environment', shell=True)
