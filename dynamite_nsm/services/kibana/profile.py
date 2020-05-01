import os
import sys

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.kibana import config as kibana_configs
from dynamite_nsm.services.kibana import process as kibana_process


class ProcessProfiler:
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
            kibana_configs.ConfigManager(configuration_directory=kibana_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable kibana.yml \n')
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return kibana_process.ProcessManager().status()['RUNNING']
        except Exception:
            return False

    @staticmethod
    def _is_listening(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        kibana_path_conf = env_dict.get('KIBANA_PATH_CONF')
        if not kibana_path_conf:
            if stderr:
                sys.stderr.write('[-] Kibana configuration directory could not be located in {}\n'
                                 ''.format(os.path.join(const.CONFIG_PATH, 'environment')))
            return False
        if not os.path.exists(os.path.join(kibana_path_conf, 'kibana.yml')):
            if stderr:
                sys.stderr.write('[-] Could not locate kibana.yml in {}\n'.format(kibana_path_conf))
            return False
        try:
            kibana_config = kibana_configs.ConfigManager(configuration_directory=kibana_path_conf)
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
