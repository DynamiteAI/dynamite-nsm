import os
import time
import signal
import logging
import subprocess
from dynamite_nsm.logger import get_logger
from multiprocessing import Process

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import utilities
from dynamite_nsm.services.logstash import config as logstash_configs
from dynamite_nsm.services.logstash import exceptions as logstash_exceptions

PID_DIRECTORY = '/var/run/dynamite/logstash/'


class ProcessManager:
    """
    An interface for start|stop|status|restart of the LogStash process
    """

    def __init__(self, stdout=True, verbose=False):

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('LOGSTASH', level=log_level, stdout=stdout)

        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('LS_PATH_CONF')
        if not self.configuration_directory:
            self.logger.error("Could not resolve LS_PATH_CONF environment variable. Is Logstash installed?")
            raise logstash_exceptions.CallLogstashProcessError(
                "Could not resolve LS_PATH_CONF environment variable. Is Logstash installed?")
        self.config = logstash_configs.ConfigManager(self.configuration_directory)
        utilities.makedirs(PID_DIRECTORY, exist_ok=True)
        utilities.set_ownership_of_file(PID_DIRECTORY, user='dynamite', group='dynamite')
        try:
            with open(os.path.join(PID_DIRECTORY, 'logstash.pid')) as pid_f:
                self.pid = int(pid_f.read()) + 1
        except (IOError, ValueError):
            self.pid = -1

    def start(self):
        """
        Start the LogStash process

        :return: True if started successfully
        """

        self.pid = -1

        def start_shell_out():
            command = 'runuser -l dynamite -c "{} {}/bin/logstash --path.settings={} &>/dev/null & echo \$! > {}"' \
                      ''.format(
                            utilities.get_environment_file_str(),
                            self.config.ls_home,
                            self.config.ls_path_conf,
                            os.path.join(PID_DIRECTORY, 'logstash.pid')
                        )
            subprocess.call(command, shell=True, cwd=self.config.ls_home)

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            self.logger.info('Logstash is already running on PID [{}]'.format(self.pid))
            return True
        retry = 0
        time.sleep(5)
        while retry < 6:
            try:
                with open(os.path.join(PID_DIRECTORY, 'logstash.pid')) as f:
                    self.pid = int(f.read()) + 1
                start_message = '[Attempt: {}] Starting LogStash on PID [{}]'.format(retry + 1, self.pid)
                self.logger.info(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(3)
                else:
                    return True
            except IOError as e:
                self.logger.warning("An issue occurred while attempting to start.")
                self.logger.debug("An issue occurred while attempting to start; {}".format(e))
                retry += 1
                time.sleep(3)
        self.logger.error("Failed to start LogStash after {} attempts.".format(retry))
        return False

    def stop(self):
        """
        Stop the LogStash process

        :return: True if stopped successfully
        """

        alive = True
        attempts = 0
        while alive:
            try:
                self.logger.info('Attempting to stop LogStash [{}]'.format(self.pid))
                if attempts > 3:
                    self.logger.warning(
                        'Attempting to force stop LogStash after {} failed attempts. [{}].'.format(attempts,
                                                                                                   self.pid))
                    sig_command = signal.SIGKILL
                else:
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)
                alive = utilities.check_pid(self.pid)
            except Exception as e:
                self.logger.error('An error occurred while attempting to stop LogStash.')
                self.logger.debug('An error occurred while attempting to stop LogStash; {}'.format(e))
                return False
        return True

    def restart(self):
        """
        Restart the LogStash process

        :return: True if started successfully
        """
        self.stop()
        return self.start()

    def status(self):
        """
        Check the status of the LogStash process

        :return: A dictionary containing the run status and relevant configuration options
        """
        log_path = os.path.join(self.config.path_logs, 'logstash-plain.log')

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'USER': 'dynamite',
            'LOGS': log_path
        }


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
