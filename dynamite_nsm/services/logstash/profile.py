import os
import sys
import json

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.logstash import config as logstash_configs
from dynamite_nsm.services.logstash import process as logstash_process


class ProcessProfiler:
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
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        env_dict = utilities.get_environment_file_dict()
        ls_home = env_dict.get('LS_HOME')
        if not ls_home:
            if stderr:
                sys.stderr.write('[-] LogStash installation directory could not be located in {}\n'.format(env_file))
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
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
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
                                 '{}\n'.format(env_file))
            return False
        elif not ef_template_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow template directory could not be located in '
                                 '{}\n'.format(env_file))
            return False
        elif not ef_geo_ip_db_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow geoip directory could not be located in '
                                 '{}\n'.format(env_file))
            return False
        elif not ef_definition_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow definitions directory could not be located in '
                                 '{}\n'.format(env_file))
            return False
        elif not syn_dict_path:
            if stderr:
                sys.stderr.write('[-] Synesis dictionary directory could not be located in '
                                 '{}\n'.format(env_file))
            return False
        elif not syn_template_path:
            if stderr:
                sys.stderr.write('[-] ElastiFlow template directory could not be located in '
                                 '{}\n'.format(env_file))
            return False
        if not os.path.exists(ef_dict_path):
            if stderr:
                sys.stderr.write('[-] ElastiFlow dictionary directory could not be located at: '
                                 '{}\n'.format(env_file))
            return False
        elif not os.path.exists(ef_template_path):
            if stderr:
                sys.stderr.write('[-] ElastiFlow template directory could not be located at: '
                                 '{}\n'.format(env_file))
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
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        env_dict = utilities.get_environment_file_dict()
        ls_path_conf = env_dict.get('LS_PATH_CONF')
        if not ls_path_conf:
            if stderr:
                sys.stderr.write('[-] LogStash configuration directory could not be located in '
                                 '{}\n'.format(env_file))
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
            logstash_configs.ConfigManager(configuration_directory=ls_path_conf)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable logstash.yml or jvm.options \n')
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return logstash_process.ProcessManager().status()['RUNNING']
        except Exception:
            return False

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running
        }
