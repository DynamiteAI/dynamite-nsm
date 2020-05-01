import os
import time
import signal
import logging
import subprocess
from multiprocessing import Process

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger

PID_DIRECTORY = '/var/run/dynamite/jupyterhub/'


class ProcessManager:
    """
    An interface for start|stop|status|restart of the JupyterHub process
    """

    def __init__(self, stdout=True, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('LAB', level=log_level, stdout=stdout)

        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('DYNAMITE_LAB_CONFIG')
        utilities.makedirs(PID_DIRECTORY, exist_ok=True)
        utilities.set_ownership_of_file(PID_DIRECTORY, user='dynamite', group='dynamite')
        try:
            with open(os.path.join(PID_DIRECTORY, 'jupyterhub.pid')) as pid_f:
                self.pid = int(pid_f.read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self):
        """
        Start the JupyterHub process

        :return: True, if started successfully
        """

        def start_shell_out():
            subprocess.call('jupyterhub -f {} &>/dev/null &'.format(
                os.path.join(self.configuration_directory, 'jupyterhub_config.py')), shell=True, stderr=subprocess.PIPE,
                stdout=None)

        utilities.makedirs(PID_DIRECTORY, exist_ok=True)

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            self.logger.info('JupyterHub is already running on PID [{}]'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            try:
                with open(os.path.join(PID_DIRECTORY, 'jupyterhub.pid')) as f:
                    self.pid = int(f.read())
                start_message = '[Attempt: {}] Starting JupyterHub on PID [{}]'.format(retry + 1, self.pid)
                self.logger.info(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(5)
                else:
                    return True
            except IOError as e:
                self.logger.warning("An issue occurred while attempting to start.")
                self.logger.debug("An issue occurred while attempting to start; {}".format(e))
                retry += 1
                time.sleep(3)
        return False

    def stop(self):
        """
        Stop the Jupyterhub process

        :return: True if stopped successfully
        """

        alive = True
        attempts = 0
        while alive:
            try:
                self.logger.info('Attempting to stop JupyterHub [{}]'.format(self.pid))
                if attempts > 3:
                    self.logger.warning(
                        'Attempting to force stop JupyterHub after {} failed attempts. [{}].'.format(attempts,
                                                                                                     self.pid))
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
                self.logger.error('An error occurred while attempting to stop JupyterHub.')
                self.logger.debug('An error occurred while attempting to stop JupyterHub; {}'.format(e))
                return False
        self.logger.info("Deleting JupyterHub PID [{}].".format(self.pid))
        utilities.safely_remove_file(os.path.join(PID_DIRECTORY, 'jupyterhub.pid'))
        return True

    def restart(self):
        """
        Restart the JupyterHub process

        :return: True if started successfully
        """

        self.stop()
        return self.start()

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


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
