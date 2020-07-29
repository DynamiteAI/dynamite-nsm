import os
import re
import subprocess

from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout=True, verbose=False):
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('ZEEK_HOME')

        try:
            process.BaseProcessManager.__init__(self, 'suricata.service', log_path=None,
                                                pid_file=None, stdout=stdout, verbose=verbose)
        except general_exceptions.CallProcessError:
            raise zeek_exceptions.CallZeekProcessError("Could not find systemctl.")

    def status(self):
        p = subprocess.Popen('{} status'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True,
                             stdout=subprocess.PIPE)
        out, err = p.communicate()
        raw_output = out.decode('utf-8')

        zeek_status = {
            'running': False,
            'subprocesses': []
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


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
