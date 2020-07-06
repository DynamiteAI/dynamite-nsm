import os
import sys

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.zeek import process as zeek_process


class ProcessProfiler:
    """
    An interface for profiling Zeek NSM
    """
    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_running = self._is_running()

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.ZEEK_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] Zeek installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        env_dict = utilities.get_environment_file_dict()
        zeek_home = env_dict.get('ZEEK_HOME')
        zeek_scripts = env_dict.get('ZEEK_SCRIPTS')
        if not zeek_home:
            if stderr:
                sys.stderr.write('[-] ZEEK_HOME installation directory could not be located in '
                                 '{}.\n'.format(env_file))
            return False
        if not zeek_scripts:
            if stderr:
                sys.stderr.write('[-] ZEEK_SCRIPTS directory could not be located in {}.\n'.format(env_file))
            return False
        if not os.path.exists(zeek_home):
            if stderr:
                sys.stderr.write('[-] ZEEK_HOME installation directory could not be located on disk at: {}.\n'.format(
                    zeek_home))
            return False
        if not os.path.exists(zeek_scripts):
            if stderr:
                sys.stderr.write('[-] ZEEK_SCRIPTS directory could not be located on disk at: {}.\n'.format(
                    zeek_scripts))
            return False
        zeek_home_directories = os.listdir(zeek_home)
        zeek_scripts_directories = os.listdir(zeek_scripts)
        if 'bin' not in zeek_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate ZEEK_HOME {}/bin directory.\n'.format(zeek_home))
            return False
        elif 'lib' not in zeek_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate ZEEK_HOME {}/lib directory.\n'.format(zeek_home))
            return False
        elif 'etc' not in zeek_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate ZEEK_HOME {}/etc directory.\n'.format(zeek_home))
            return False
        if 'site' not in zeek_scripts_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate ZEEK_SCRIPTS {}/site directory.\n'.format(zeek_scripts))
            return False
        return True

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }

    @staticmethod
    def _is_running():
        env_dict = utilities.get_environment_file_dict()
        zeek_home = env_dict.get('ZEEK_HOME')
        if zeek_home:
            return zeek_process.ProcessManager().status()['RUNNING']
        return False
