import os
import sys
import json
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities


class ModuleProfile:
    """
    An Interface for determining whether PF_RING is installed/configured/running properly.
    """
    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_running = self._is_running()

    def __str__(self):
        return json.dumps({
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }, indent=1)

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.PF_RING_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] PF_RING installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        pf_ring_home = env_dict.get('PF_RING_HOME')
        if not pf_ring_home:
            if stderr:
                sys.stderr.write('[-] PF_RING installation directory could not be located in {} \n'.format(
                    os.path.join(const.CONFIG_PATH, 'environment')))
            return False
        if not os.path.exists(pf_ring_home):
            if stderr:
                sys.stderr.write('[-] PF_RING installation directory could not be located on disk at: {}.\n'.format(
                    pf_ring_home))
            return False
        pf_ring_home_files_and_dirs = os.listdir(pf_ring_home)
        if 'bin' not in pf_ring_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate PF_RING {}/bin directory.\n'.format(pf_ring_home))
            return False
        if 'lib' not in pf_ring_home_files_and_dirs:
            if stderr:
                sys.stderr.write('[-] Could not locate PF_RING {}/lib directory.\n'.format(pf_ring_home))
            return False
        return True

    @staticmethod
    def _is_running():
        p = subprocess.Popen('lsmod', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, close_fds=True)
        out, err = p.communicate()
        return 'pf_ring' in out.decode('utf-8')

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }