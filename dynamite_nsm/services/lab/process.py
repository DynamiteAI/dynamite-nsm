import os
import sys
import time
import signal
import subprocess
from multiprocessing import Process

from dynamite_nsm import utilities
from dynamite_nsm.services.lab import config as lab_configs


class ProcessManager:
    """
    An interface for start|stop|status|restart of the JupyterHub process
    """
    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('DYNAMITE_LAB_CONFIG')
        try:
            self.pid = int(open('/var/run/dynamite/jupyterhub/jupyterhub.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the JupyterHub process
        :param stdout: Print output to console
        :return: True, if started successfully
        """
        def start_shell_out():
            subprocess.call('jupyterhub -f {} &>/dev/null &'.format(
                os.path.join(self.configuration_directory, 'jupyterhub_config.py')), shell=True, stderr=subprocess.PIPE,
                stdout=None)

        if not os.path.exists('/var/run/dynamite/jupyterhub/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/jupyterhub/'), shell=True)

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] JupyterHub is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting JupyterHub on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/jupyterhub/jupyterhub.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting JupyterHub on PID [{}]\n'.format(retry + 1, self.pid)
                if stdout:
                    sys.stdout.write(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(5)
                else:
                    return True
            except IOError:
                if stdout:
                    sys.stdout.write(start_message)
                retry += 1
                time.sleep(3)
        return False

    def stop(self, stdout=False):
        """
        Stop the Jupyterhub process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop JupyterHub [{}]\n'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGKILL
                else:
                    # Kill the zombie after the third attempt of asking it to kill itself
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)

                alive = utilities.check_pid(self.pid)
            except Exception as e:
                sys.stderr.write('[-] An error occurred while attempting to stop JupyterHub: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the JupyterHub process

        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

    def status(self):
        """
        Check the status of the JupyterHub process

        :return: A dictionary containing the run status and relevant configuration options
        """

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'USER': 'root'
        }


def change_sdk_elasticsearch_password(password='changeme', prompt_user=True, stdout=False):
    """
    Change the DynamiteSDK to ElasticSearch password

    :param password: The password that the SDK will use to connect to ElasticSearch
    :param prompt_user: Whether or not to warn the user
    :param stdout: Print output to console
    :return: True if changed successfully
    """
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('DYNAMITE_LAB_CONFIG')
    if prompt_user:
        resp = utilities.prompt_input(
            'Changing the SDK password can cause your notebooks to lose communication with ElasticSearch. '
            'Are you sure you wish to continue? [no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    dynamite_lab_config = lab_configs.ConfigManager(configuration_directory=configuration_directory)
    dynamite_lab_config.elasticsearch_password = password
    dynamite_lab_config.write_config()
    return True
