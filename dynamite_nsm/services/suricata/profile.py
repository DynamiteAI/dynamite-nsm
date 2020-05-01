import os
import sys

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import process as suricata_process


class ProcessProfiler:
    """
    An interface for profiling Suricata IDS
    """
    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_running = self._is_running()

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME)):
            if stderr:
                sys.stderr.write('[-] Zeek installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        env_dict = utilities.get_environment_file_dict()
        suricata_home = env_dict.get('SURICATA_HOME')
        suricata_config = env_dict.get('SURICATA_CONFIG')
        if not suricata_home:
            if stderr:
                sys.stderr.write('[-] SURICATA_HOME installation directory could not be located in '
                                 '{}\n'.format(env_file))
            return False
        if not suricata_config:
            if stderr:
                sys.stderr.write('[-] SURICATA_CONFIG directory could not be located in {}\n'.format(env_file))
            return False
        if not os.path.exists(suricata_home):
            if stderr:
                sys.stderr.write('[-] SURICATA_HOME installation directory could not be located on disk at: '
                                 '{}.\n'.format(suricata_home))
            return False
        if not os.path.exists(suricata_config):
            if stderr:
                sys.stderr.write('[-] SURICATA_CONFIG directory could not be located on disk at: {}.\n'.format(
                    suricata_config))
            return False
        suricata_home_directories = os.listdir(suricata_home)
        suricata_config_directories = os.listdir(suricata_config)
        if 'bin' not in suricata_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate SURICATA_HOME {}/bin directory.\n'.format(suricata_home))
            return False
        elif 'lib' not in suricata_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate SURICATA_HOME {}/lib directory.\n'.format(suricata_home))
            return False
        elif 'include' not in suricata_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate SURICATA_HOME {}/include directory.\n'.format(suricata_home))
            return False
        if 'rules' not in suricata_config_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate SURICATA_CONFIG {}/rules directory.\n'.format(suricata_config))
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return suricata_process.ProcessManager().status()['RUNNING']
        except Exception:
            return False

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }
