import os
import sys
import time
import signal
import subprocess
from multiprocessing import Process

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import utilities
from dynamite_nsm.services.logstash import config as logstash_configs
from dynamite_nsm.services.logstash import exceptions as logstash_exceptions


class ProcessManager:
    """
    An interface for start|stop|status|restart of the LogStash process
    """

    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('LS_PATH_CONF')
        if not self.configuration_directory:
            raise logstash_exceptions.CallLogstashProcessError(
                "Could not resolve LS_PATH_CONF environment variable. Is Logstash installed?")
        self.config = logstash_configs.ConfigManager(self.configuration_directory)
        if not os.path.exists('/var/run/dynamite/logstash/'):
            utilities.makedirs('/var/run/dynamite/logstash/', exist_ok=True)
        utilities.set_ownership_of_file('/var/run/dynamite', user='dynamite', group='dynamite')
        try:
            self.pid = int(open('/var/run/dynamite/logstash/logstash.pid').read()) + 1
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the LogStash process
        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.pid = -1

        def start_shell_out():
            command = 'runuser -l dynamite -c "{} {}/bin/logstash ' \
                      '--path.settings={} &>/dev/null & echo \$! > /var/run/dynamite/logstash/logstash.pid"'.format(
                utilities.get_environment_file_str(), self.config.ls_home, self.config.ls_path_conf)
            subprocess.call(command, shell=True, cwd=self.config.ls_home)
        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] Logstash is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting Logstash on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/logstash/logstash.pid') as f:
                    self.pid = int(f.read()) + 1
                start_message = '[+] [Attempt: {}] Starting LogStash on PID [{}]\n'.format(retry + 1, self.pid)
                if stdout:
                    sys.stdout.write(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(3)
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
        Stop the LogStash process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop LogStash [{}]\n'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGKILL
                else:
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)
                alive = utilities.check_pid(self.pid)
            except Exception as e:
                sys.stderr.write('[-] An error occurred while attempting to stop LogStash: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the LogStash process

        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

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


def start(stdout=True):
    ProcessManager().start(stdout)


def stop(stdout=True):
    ProcessManager().stop(stdout)


def restart(stdout=True):
    ProcessManager().restart(stdout)


def status():
    return ProcessManager().status()
