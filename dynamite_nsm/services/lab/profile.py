import os
import sys
import json
import subprocess

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.lab import config as lab_configs
from dynamite_nsm.services.lab import process as lab_process


class ProcessProfiler:
    """
    Interface for determining whether JupyterHub is installed/configured/running properly.
    """
    def __init__(self, stderr=False):
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_configured = self._is_configured(stderr=stderr)
        self.is_running = self._is_running()

    def __str__(self):
        return json.dumps({
            'INSTALLED': self.is_installed,
            'CONFIGURED': self.is_configured,
            'RUNNING': self.is_running,
        }, indent=1)

    @staticmethod
    def _is_installed(stderr=False):
        try:
            p = subprocess.Popen('jupyterhub --version', shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            p.communicate()
            if p.returncode != 0:
                sys.stderr.write('[-] Jupyterhub is not installed.\n')
                return False
            if not utilities.check_user_exists('jupyter'):
                sys.stderr.write('[-] jupyter user was not created.\n')
                return False
        except OSError:
            if stderr:
                sys.stderr.write('[-] Could not locate JupyterHub in $PATH.')
            return False
        return True

    @staticmethod
    def _is_configured(stderr=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            env_dict = utilities.get_environment_file_dict()
        except IOError:
            if stderr:
                sys.stderr.write('[-] DynamiteLab environment variables haven\'t been created.\n')
            return False
        dynamite_lab_config = env_dict.get('DYNAMITE_LAB_CONFIG')
        if not dynamite_lab_config:
            if stderr:
                sys.stderr.write('[-] DynamiteLab configuration directory could not be located in '
                                 '{}\n'.format(env_file))
            return False
        if not os.path.exists(dynamite_lab_config):
            if stderr:
                sys.stderr.write('[-] DynamiteLab configuration directory could not be located at {}.\n'.format(
                    dynamite_lab_config))
            return False
        try:
            lab_configs.ConfigManager(configuration_directory=dynamite_lab_config)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable config.cfg \n')
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return lab_process.ProcessManager().status()['RUNNING']
        except Exception:
            return False

    def get_profile(self):
        return {
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }