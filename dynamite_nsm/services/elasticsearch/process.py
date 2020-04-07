import os
import sys
import time
import signal
import subprocess
from multiprocessing import Process

from dynamite_nsm import utilities
from dynamite_nsm.services.elasticsearch import config as elastic_configs


class ProcessManager:
    """
    An interface for start|stop|status|restart of the ElasticSearch process
    """
    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('ES_PATH_CONF')
        self.config = elastic_configs.ConfigManager(self.configuration_directory)
        try:
            self.pid = int(open('/var/run/dynamite/elasticsearch/elasticsearch.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the ElasticSearch process
        :param stdout: Print output to console
        :return: True, if started successfully
        """
        def start_shell_out():
            subprocess.call('runuser -l dynamite -c "{} {}/bin/elasticsearch '
                            '-p /var/run/dynamite/elasticsearch/elasticsearch.pid --quiet &>/dev/null &"'
                            ''.format(utilities.get_environment_file_str(), self.config.es_home), shell=True)
        if not os.path.exists('/var/run/dynamite/elasticsearch/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/elasticsearch/'), shell=True)
        utilities.set_ownership_of_file('/var/run/dynamite', user='dynamite', group='dynamite')

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] ElasticSearch is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting ElasticSearch on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/elasticsearch/elasticsearch.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting ElasticSearch on PID [{}]\n'.format(retry + 1, self.pid)
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
        Stop the ElasticSearch process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop ElasticSearch [{}]\n'.format(self.pid))
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
                sys.stderr.write('[-] An error occurred while attempting to stop ElasticSearch: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the ElasticSearch process

        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

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
