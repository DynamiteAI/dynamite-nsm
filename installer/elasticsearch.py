import os
import sys
import time
import shutil
import tarfile
import subprocess

from installer import const
from installer import utilities

CONFIGURATION_DIRECTORY = '/etc/dynamite/elasticsearch/'
INSTALL_DIRECTORY = '/opt/dynamite/elasticsearch/'
LOG_DIRECTORY = '/var/log/dynamite/elasticsearch/'


class ElasticConfigurator:

    def __init__(self, configuration_directory):
        self.configuration_directory = configuration_directory
        self.es_config_options = self._parse_elasticyaml()
        self.jvm_config_options = self._parse_jvm_options()

    def _parse_elasticyaml(self):
        es_config_options = {}
        for line in open(os.path.join(self.configuration_directory, 'elasticsearch.yml')).readlines():
            if not line.startswith('#'):
                k, v = line.strip().split(':')
                es_config_options[k] = v
        return es_config_options

    def _parse_jvm_options(self):
        jvm_options = {}
        for line in open(os.path.join(self.configuration_directory, 'jvm.options')).readlines():
            if not line.startswith('#') and '-Xms' in line:
                jvm_options['initial_memory'] = line.replace('-Xms', '').strip()
            elif not line.startswith('#') and '-Xmx' in line:
                jvm_options['maximum_memory'] = line.replace('-Xmx', '').strip()
        return jvm_options

    def _overwrite_jvm_options(self):
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
        return self.es_config_options.get('cluster.name')

    def get_network_host(self):
        return self.es_config_options.get('network.host')

    def get_network_port(self):
        return self.es_config_options.get('http.port')

    def get_data_path(self):
        return self.es_config_options.get('path.data')

    def get_log_path(self):
        return self.es_config_options.get('path.logs')

    def get_jvm_initial_memory(self):
        return self.jvm_config_options.get('initial_memory')

    def get_jvm_maximum_memory(self):
        return self.jvm_config_options.get('maximum_memory')

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

    def set_jvm_initial_memory(self, gigs):
        self.jvm_config_options['initial_memory'] = str(int(gigs)) + 'g'

    def set_jvm_maximum_memory(self, gigs):
        self.jvm_config_options['maximum_memory'] = str(int(gigs)) + 'g'

    def write_configs(self):
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
                elastic_search_config_obj.write('{}: {}\n'.format(k, v))
        self._overwrite_jvm_options()


class ElasticInstaller:

    def __init__(self,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY,
                 log_directory=LOG_DIRECTORY):

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.elasticsearch_downloaded = False
        self.elasticsearch_extracted = False
        self.java_downloaded = False
        self.java_extracted = False

    def download_elasticsearch(self, stdout=False):
        for url in open(const.ELASTICSEARCH_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.ELASTICSEARCH_ARCHIVE_NAME, stdout):
                self.elasticsearch_downloaded = True
                break

    def download_java(self, stdout=False):
        for url in open(const.JAVA_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.JAVA_ARCHIVE_NAME, stdout):
                self.java_downloaded = True
                break

    def extract_elasticsearch(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.ELASTICSEARCH_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
            self.elasticsearch_extracted = True
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def extract_java(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.JAVA_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.JAVA_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
            self.java_extracted = True
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_elasticsearch(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating dynamite install/configuration/logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.install_directory, 'data')), shell=True)
        subprocess.call('mkdir -p {}'.format('/var/run/dynamite/elasticsearch/'), shell=True)
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
                shutil.move(os.path.join(const.INSTALL_CACHE, 'elasticsearch-7.1.1/{}'.format(path)),
                            self.configuration_directory)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, 'elasticsearch-7.1.1/{}'.format(path)),
                            self.install_directory)
            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        if 'ES_PATH_CONF' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating ElasticSearch default configuration path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo ES_PATH_CONF="{}" >> /etc/environment'.format(self.configuration_directory),
                            shell=True)
        if 'ES_HOME' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating ElasticSearch default home path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo ES_HOME="{}" >> /etc/environment'.format(self.install_directory),
                            shell=True)
        subprocess.call('source /etc/environment', shell=True)
        sys.stdout.write('[+] Overwriting default configuration.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'elasticsearch', 'elasticsearch.yml'),
                    self.configuration_directory)
        utilities.set_ownership_of_file('/etc/dynamite/')
        utilities.set_ownership_of_file('/opt/dynamite/')
        utilities.set_ownership_of_file('/var/log/dynamite')
        utilities.set_ownership_of_file('/var/run/dynamite')
        es_config = ElasticConfigurator(configuration_directory=self.configuration_directory)
        sys.stdout.write('[+] Setting up JVM default heap settings [4GB]\n')
        es_config.set_jvm_initial_memory(4)
        es_config.set_jvm_maximum_memory(4)
        es_config.write_configs()
        sys.stdout.write('[+] Setting up Max File Handles [65535] VM Max Map Count [262144] \n')
        utilities.update_user_file_handle_limits()
        utilities.update_sysctl()

    def setup_java(self):
        subprocess.call('mkdir -p /usr/lib/jvm', shell=True)
        try:
            shutil.move(os.path.join(const.INSTALL_CACHE, 'jdk-11.0.2'), '/usr/lib/jvm/')
        except shutil.Error as e:
            sys.stderr.write('[-] JVM already exists at path specified. [{}]\n'.format(e))
        try:
            os.symlink('/usr/lib/jvm/jdk-11.0.2/bin/java', '/usr/bin/java')
        except Exception as e:
            sys.stderr.write('[-] Java Sym-link already exists at path specified. [{}]\n'.format(e))
        if 'JAVA_HOME' not in open('/etc/environment').read():
            subprocess.call('echo JAVA_HOME="/usr/lib/jvm/jdk-11.0.2/" >> /etc/environment', shell=True)
        subprocess.call('source /etc/environment', shell=True)


class ElasticProcess:

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        self.configuration_directory = configuration_directory
        self.config = ElasticConfigurator(self.configuration_directory)

    def start(self):
        subprocess.call('runuser -l dynamite -c "export JAVA_HOME=$JAVA_HOME && export ES_PATH_CONF=$ES_PATH_CONF '
                        '&& $ES_HOME/bin/elasticsearch -p /var/run/elasticsearch/elasticsearch.pid --quiet"',
                        shell=True)
