import os
import re
import logging
import subprocess

from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions


class ProcessManager:

    def __init__(self, stdout=True, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('ZEEK', level=log_level, stdout=stdout)

        self.stdout = stdout,
        self.verbose = verbose
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('ZEEK_HOME')
        if not self.install_directory:
            self.logger.error("Could not resolve ZEEK_HOME environment_variable. Is Zeek installed?")
            raise zeek_exceptions.CallZeekProcessError(
                "Could not resolve ZEEK_HOME environment_variable. Is Zeek installed?")
        try:
            self.sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise zeek_exceptions.CallZeekProcessError("Could not find systemctl.")

    def start(self):
        """
        Start Zeek cluster via broctl

        :return: True, if started successfully
        """
        self.logger.info('Attempting to start Zeek cluster.')
        return self.sysctl.start('zeek')

    def stop(self):
        """
        Stop Zeek cluster via broctl

        :return: True, if stopped successfully
        """
        self.logger.info('Attempting to stop Zeek cluster.')
        return self.sysctl.stop('zeek')

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

    def restart(self):
        """
        Restart the Zeek process via broctl

        :return: True if restarted successfully
        """
        return self.sysctl.restart('zeek')


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
