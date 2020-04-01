import os
import sys
import time
import signal
import subprocess
from multiprocessing import Process

from dynamite_nsm import utilities
from dynamite_nsm.services.filebeat import config as filebeat_configs


class ProcessManager:
    """
    An interface for start|stop|status|restart of the Filebeat process
    """

    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('FILEBEAT_HOME')
        self.config = filebeat_configs.ConfigManager(self.install_directory)

        if not os.path.exists('/var/run/dynamite/filebeat/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/filebeat/'), shell=True)

        try:
            self.pid = int(open('/var/run/dynamite/filebeat/filebeat.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the Filebeat daemon
        :param stdout: Print output to console
        :return: True if started successfully
        """
        def start_shell_out():
            command = '{}/filebeat -c {}/filebeat.yml & echo $! > /var/run/dynamite/filebeat/filebeat.pid'.format(
                self.config.install_directory, self.config.install_directory)
            subprocess.call(command, shell=True)
        if stdout:
            sys.stdout.write('[+] Starting Filebeat\n')
        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] Filebeat is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting FileBeat on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/filebeat/filebeat.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting FileBeat on PID [{}]\n'.format(retry + 1, self.pid)
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
                    sys.stdout.write('[+] Attempting to stop Filebeat [{}]\n'.format(self.pid))
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
                sys.stderr.write('[-] An error occurred while attempting to stop Filebeat: {}\n'.format(e))
                return False
        return True
