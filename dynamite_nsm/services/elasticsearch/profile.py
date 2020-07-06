import os
import sys
import json

from dynamite_nsm import const
from dynamite_nsm import utilities

from dynamite_nsm.services.elasticsearch import config as elastic_configs
from dynamite_nsm.services.elasticsearch import process as elastic_process


class ProcessProfiler:
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
        if not utilities.check_user_exists('dynamite'):
            sys.stderr.write('[-] dynamite user was not created.\n')
            return False
        return True

    @staticmethod
    def _is_configured(stderr=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
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
                                 '{}\n'.format(env_file))
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
            elastic_configs.ConfigManager(configuration_directory=es_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable elasticsearch.yml or jvm.options \n')
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return elastic_process.ProcessManager().status()['RUNNING']
        except Exception:
            return False

    @staticmethod
    def _is_listening(stderr=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
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
                                 '{}\n'.format(env_file))
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
            es_config = elastic_configs.ConfigManager(configuration_directory=es_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable elasticsearch.yml or jvm.options \n')
            return False
        host = es_config.network_host
        port = es_config.http_port
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
