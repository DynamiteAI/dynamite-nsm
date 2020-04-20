import os
import sys

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.filebeat import process as filebeat_process


class ProcessProfiler:

    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_running = self._is_running()

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] FileBeat installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        env_dict = utilities.get_environment_file_dict()
        filebeat_home = env_dict.get('FILEBEAT_HOME')
        if not filebeat_home:
            if stderr:
                sys.stderr.write(
                    '[-] FILEBEAT_HOME installation directory could not be located in {}.\n'.format(env_file))
            return False
        if not os.path.exists(filebeat_home):
            if stderr:
                sys.stderr.write(
                    '[-] FILEBEAT_HOME installation directory could not be located on disk at: {}.\n'.format(
                        filebeat_home))
            return False
        filebeat_home_directories_and_files = os.listdir(filebeat_home)
        if 'filebeat' not in filebeat_home_directories_and_files:
            if stderr:
                sys.stderr.write('[-] Could not locate FILEBEAT {}/filebeat binary.\n'.format(filebeat_home))
            return False
        if 'filebeat.yml' not in filebeat_home_directories_and_files:
            if stderr:
                sys.stderr.write('[-] Could not locate FILEBEAT {}/filebeat.yml config.\n'.format(filebeat_home))
            return False
        return True

    @staticmethod
    def _is_running():
        env_dict = utilities.get_environment_file_dict()
        filebeat_home = env_dict.get('FILEBEAT_HOME')
        if filebeat_home:
            return filebeat_process.ProcessManager().status()['RUNNING']
        return False

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }
