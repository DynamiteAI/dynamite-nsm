import os
import time
import signal
import logging
import subprocess
from multiprocessing import Process

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.filebeat import config as filebeat_configs
from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions

PID_DIRECTORY = '/var/run/dynamite/filebeat/'


class ProcessManager:
    """
    An interface for start|stop|status|restart of the Filebeat process
    """

    def __init__(self, stdout=True, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('FILEBEAT', level=log_level, stdout=stdout)

        self.stdout = stdout,
        self.verbose = verbose
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('FILEBEAT_HOME')
        if not self.install_directory:
            self.logger.error("Could not resolve FILEBEAT_HOME environment variable. Is Filebeat installed?")
            raise filebeat_exceptions.CallFilebeatProcessError(
                "Could not resolve FILEBEAT_HOME environment variable. Is Filebeat installed?")
        self.config = filebeat_configs.ConfigManager(self.install_directory)

        if not os.path.exists(PID_DIRECTORY):
            utilities.makedirs(PID_DIRECTORY, exist_ok=True)
        try:
            with open(os.path.join(PID_DIRECTORY, 'filebeat.pid')) as pid_f:
                self.pid = int(pid_f.read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self):
        """
        Start the Filebeat daemon

        :return: True if started successfully
        """

        def start_shell_out():
            command = '{}/filebeat -c {}/filebeat.yml & echo $! > {}'.format(
                self.config.install_directory, self.config.install_directory,
                os.path.join(PID_DIRECTORY, 'filebeat.pid'))
            subprocess.call(command, shell=True)

        self.logger.info('Starting Filebeat.')
        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            self.logger.info('Filebeat is already running on PID [{}].'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            try:
                with open(os.path.join(PID_DIRECTORY, 'filebeat.pid')) as f:
                    self.pid = int(f.read())
                start_message = '[Attempt: {}] Starting FileBeat on PID [{}]'.format(retry + 1, self.pid)
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
        self.logger.error("Failed to start FileBeat after {} attempts.".format(retry))
        return False

    def status(self):
        """
        Check the status of the FileBeat process

        :return: A dictionary containing the run status and relevant configuration options
        """
        log_path = os.path.join(self.config.install_directory, 'logs', 'filebeat')

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'LOGS': log_path
        }

    def stop(self):
        """
        Stop the FileBeat process

        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                self.logger.info('Attempting to stop Filebeat [{}].'.format(self.pid))
                if attempts > 3:
                    self.logger.warning(
                        'Attempting to force stop Filebeat after 3 failed attempts. [{}].'.format(self.pid))
                    sig_command = signal.SIGKILL
                else:
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)
                alive = utilities.check_pid(self.pid)
            except Exception as e:
                self.logger.error('An error occurred while attempting to stop Filebeat.')
                self.logger.debug('An error occurred while attempting to stop Filebeat; {}'.format(e))
                return False
        self.logger.info("Deleting Filebeat PID [{}].".format(self.pid))
        utilities.safely_remove_file(os.path.join(PID_DIRECTORY, 'filebeat.pid'))
        return True

    def restart(self):
        """
        Restart the FileBeat process

        :return: True if started successfully
        """
        self.stop()
        return self.start()


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
