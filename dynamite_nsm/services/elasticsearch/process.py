import os
import time
import signal
import logging
import subprocess
from multiprocessing import Process

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.elasticsearch import config as elastic_configs
from dynamite_nsm.services.elasticsearch import exceptions as elastic_exceptions

PID_DIRECTORY = '/var/run/dynamite/elasticsearch/'


class ProcessManager:
    """
    An interface for start|stop|status|restart of the ElasticSearch process
    """

    def __init__(self, stdout=True, verbose=False):
        self.stdout = stdout
        self.verbose = verbose

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('ELASTICSEARCH', level=log_level, stdout=stdout)

        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('ES_PATH_CONF')
        if not self.configuration_directory:
            self.logger.error("Could not resolve ES_PATH_CONF environment variable. Is ElasticSearch installed?")
            raise elastic_exceptions.CallElasticProcessError(
                "Could not resolve ES_PATH_CONF environment variable. Is ElasticSearch installed?")
        self.config = elastic_configs.ConfigManager(self.configuration_directory)
        try:
            with open(os.path.join(PID_DIRECTORY, 'elasticsearch.pid')) as pid_f:
                self.pid = int(pid_f.read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self):
        """
        Start the ElasticSearch process

        :return: True, if started successfully
        """

        def start_shell_out():
            subprocess.call('runuser -l dynamite -c "{} {}/bin/elasticsearch '
                            '-p {} --quiet &>/dev/null &"'
                            ''.format(utilities.get_environment_file_str(), self.config.es_home,
                                      os.path.join(PID_DIRECTORY, 'elasticsearch.pid')), shell=True)

        if not os.path.exists(PID_DIRECTORY):
            utilities.makedirs(PID_DIRECTORY, exist_ok=True)
        utilities.set_ownership_of_file(PID_DIRECTORY, user='dynamite', group='dynamite')

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            self.logger.info('ElasticSearch is already running on PID [{}]'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            try:
                with open(os.path.join(PID_DIRECTORY, 'elasticsearch.pid')) as f:
                    self.pid = int(f.read())
                start_message = '[Attempt: {}] Starting ElasticSearch on PID [{}]'.format(retry + 1, self.pid)
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
        self.logger.error("Failed to start ElasticSearch after {} attempts.".format(retry))
        return False

    def stop(self):
        """
        Stop the ElasticSearch process

        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                self.logger.info('Attempting to stop ElasticSearch [{}]'.format(self.pid))
                if attempts > 3:
                    self.logger.warning(
                        'Attempting to force stop ElasticSearch after {} failed attempts. [{}].'.format(attempts,
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
                self.logger.error('An error occurred while attempting to stop ElasticSearch.')
                self.logger.debug('An error occurred while attempting to stop ElasticSearch; {}'.format(e))
                return False
        self.logger.info("Deleting ElasticSearch PID [{}].".format(self.pid))
        utilities.safely_remove_file(os.path.join(PID_DIRECTORY, 'elasticsearch.pid'))
        return True

    def restart(self):
        """
        Restart the ElasticSearch process

        :return: True if started successfully
        """
        self.stop()
        return self.start()

    def status(self):
        """
        Check the status of the ElasticSearch process

        :return: A dictionary containing the run status and relevant configuration options
        """
        log_path = os.path.join(self.config.path_logs, self.config.cluster_name + '.log')

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
