import os
import sys
import time
import signal
import subprocess

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import config as suricata_configs
from dynamite_nsm.services.suricata import exceptions as suricata_exceptions


class ProcessManager:
    """
    An interface for start|stop|status|restart of the Suricata process
    """

    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('SURICATA_HOME')
        self.configuration_directory = self.environment_variables.get('SURICATA_CONFIG')
        if not self.install_directory:
            raise suricata_exceptions.CallSuricataProcessError(
                "Could not resolve SURICATA_HOME environment_variable. Is Suricata installed?")
        elif not self.configuration_directory:
            raise suricata_exceptions.CallSuricataProcessError(
                "Could not resolve SURICATA_CONFIG environment_variable. Is Suricata installed?")
        self.config = suricata_configs.ConfigManager(self.configuration_directory)

        try:
            self.pid = int(open('/var/run/dynamite/suricata/suricata.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start Suricata IDS process in daemon mode

        :param stdout: Print output to console
        :return: True, if started successfully
        """
        if not os.path.exists('/var/run/dynamite/suricata/'):
            utilities.makedirs('/var/run/dynamite/suricata/', exist_ok=True)
        p = subprocess.Popen('bin/suricata -i {} -D --pidfile /var/run/dynamite/suricata/suricata.pid -c {}'.format(
            self.config.af_packet_interfaces[0]['interface'],
            os.path.join(self.configuration_directory, 'suricata.yaml')), shell=True, cwd=self.install_directory)
        p.communicate()
        retry = 0
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting Suricata on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/suricata/suricata.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting Suricata on PID [{}]\n'.format(retry + 1, self.pid)
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
        Stop the Suricata process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop Suricata [{}]\n'.format(self.pid))
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
                sys.stderr.write('[-] An error occurred while attempting to stop Suricata: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the Suricata process

        :param stdout: Print output to console
        :return: True if restarted successfully
        """
        if stdout:
            sys.stdout.write('[+] Attempting to restart Suricata IDS.\n')
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

    def status(self):
        """
        Check the status of the Suricata process

        :return: A dictionary containing the run status and relevant configuration options
        """
        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'LOG': os.path.join(self.config.default_log_directory, 'suricata.log')
        }


def start(stdout=True):
    ProcessManager().start(stdout)


def stop(stdout=True):
    ProcessManager().stop(stdout)


def restart(stdout=True):
    ProcessManager().restart(stdout)


def status():
    return ProcessManager().status()
