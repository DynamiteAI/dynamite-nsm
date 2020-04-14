import os
import sys
import time
import signal
import subprocess
from multiprocessing import Process

from dynamite_nsm import utilities
from dynamite_nsm.services.kibana import config as kibana_configs
from dynamite_nsm.services.kibana import exceptions as kibana_exceptions


class ProcessManager:
    """
    An interface for start|stop|status|restart of the Kibana process
    """
    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('KIBANA_PATH_CONF')
        if not self.configuration_directory:
            raise kibana_exceptions.CallKibanaProcessError(
                "Could not resolve KIBANA_PATH_CONF environment variable. Is Kibana installed?")
        self.config = kibana_configs.ConfigManager(self.configuration_directory)
        try:
            self.pid = int(open('/var/run/dynamite/kibana/kibana.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the Kibana process

        :param stdout: Print output to console
        :return: True, if started successfully
        """
        def start_shell_out():

            # We use su instead of runuser here because of nodes' weird dependency on PAM
            # when calling from within a sub-shell
            subprocess.call('su -l dynamite -c "{}/bin/kibana -c {} -l {} & > /dev/null &"'.format(
                                    self.config.kibana_home,
                                    os.path.join(self.config.kibana_path_conf, 'kibana.yml'),
                                    os.path.join(self.config.kibana_logs, 'kibana.log')
                                ), shell=True, env=utilities.get_environment_file_dict())

        if not os.path.exists('/var/run/dynamite/kibana/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/kibana/'), shell=True)
        utilities.set_ownership_of_file('/var/run/dynamite', user='dynamite', group='dynamite')

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] Kibana is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting Kibana on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/kibana/kibana.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting Kibana on PID [{}]\n'.format(retry + 1, self.pid)
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
        Stop the Kibana process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop Kibana [{}]\n'.format(self.pid))
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
                sys.stderr.write('[-] An error occurred while attempting to stop Kibana: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the Kibana process

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
        log_path = os.path.join(self.config.kibana_logs, 'kibana.log')

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'USER': 'dynamite',
            'LOGS': log_path
        }

    def optimize(self, stdout=False):
        if not os.path.exists('/var/run/dynamite/kibana/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/kibana/'), shell=True)
        utilities.set_ownership_of_file('/var/run/dynamite', user='dynamite', group='dynamite')
        if stdout:
            sys.stdout.write('[+] Optimizing Kibana Libraries.\n')

        # Kibana initially has to be called as root due to a process forking issue when using runuser
        # builtin
        subprocess.call('{}/bin/kibana --optimize --allow-root'.format(
            self.config.kibana_home,
        ), shell=True, env=utilities.get_environment_file_dict())
        # Pass permissions back to dynamite user
        utilities.set_ownership_of_file(self.config.kibana_logs, user='dynamite', group='dynamite')


def start(stdout=True):
    ProcessManager().start(stdout)


def stop(stdout=True):
    ProcessManager().stop(stdout)


def restart(stdout=True):
    ProcessManager().restart(stdout)


def status():
    return ProcessManager().status()
