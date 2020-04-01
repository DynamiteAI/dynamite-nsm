import os
import re
import sys
import subprocess
from dynamite_nsm import utilities


class ProcessManager:

    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('ZEEK_HOME')

    def start(self, stdout=False):
        """
        Start Zeek cluster via broctl

        :param stdout: Print output to console
        :return: True, if started successfully
        """
        if stdout:
            sys.stdout.write('[+] Attempting to start Zeek cluster.\n')
        p = subprocess.Popen('{} deploy'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0

    def stop(self, stdout=False):
        """
        Stop Zeek cluster via broctl

        :param stdout: Print output to console
        :return: True, if stopped successfully
        """
        if stdout:
            sys.stdout.write('[+] Attempting to stop Zeek cluster.\n')
        p = subprocess.Popen('{} stop'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0

    def status(self):
        """
        Check the status of all workers, proxies, and manager in Zeek cluster

        :return: A string containing the results outputted from 'broctl status'
        """
        p = subprocess.Popen('{} status'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True,
                             stdout=subprocess.PIPE)
        out, err = p.communicate()
        raw_output = out.decode('utf-8')

        zeek_status = {
            'RUNNING': False,
            'SUBPROCESSES': []
        }
        zeek_subprocesses = []
        for line in raw_output.split('\n')[1:]:
            tokenized_line = re.findall(r'\S+', line)
            if len(tokenized_line) == 8:
                name, _type, host, status, pid, _, _, _ = tokenized_line
                zeek_status['RUNNING'] = True
            elif len(tokenized_line) == 4:
                name, _type, host, status = tokenized_line
                pid = None
            else:
                continue
            zeek_subprocesses.append(
                {
                    'process_name': name,
                    'process_type': _type,
                    'host': host,
                    'status': status,
                    'pid': pid
                }
            )
        zeek_status['SUBPROCESSES'] = zeek_subprocesses
        return zeek_status

    def restart(self, stdout=False):
        """
        Restart the Zeek process via broctl

        :param stdout: Print output to console
        :return: True if restarted successfully
        """
        if stdout:
            sys.stdout.write('[+] Attempting to restart Zeek cluster.\n')
        p = subprocess.Popen('{} restart'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0
