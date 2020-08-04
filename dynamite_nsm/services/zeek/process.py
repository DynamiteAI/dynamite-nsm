import os
import re
import textwrap
import subprocess

import tabulate

from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('ZEEK_HOME')

        try:
            process.BaseProcessManager.__init__(self, 'zeek.service', 'zeek', log_path=None,
                                                pid_file=None, stdout=stdout, verbose=verbose,
                                                pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            raise zeek_exceptions.CallZeekProcessError("Could not find systemctl.")

    def status(self):
        p = subprocess.Popen('{} status'.format(os.path.join(self.install_directory, 'bin', 'zeekctl')), shell=True,
                             stdout=subprocess.PIPE)
        out, err = p.communicate()
        raw_output = out.decode('utf-8')
        systemd_info = self.sysctl.status('zeek.service')
        systemd_info_dict = {
            'command': systemd_info.cmd,
            'exit_code': systemd_info.exit,
        }

        zeek_status = {
            'running': False
        }
        zeek_subprocesses = []
        for line in raw_output.split('\n')[1:]:
            tokenized_line = re.findall(r'\S+', line)
            if len(tokenized_line) == 8:
                name, _type, host, status, pid, _, _, _ = tokenized_line
                zeek_status['running'] = True
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
        if self.verbose:
            zeek_status['subprocesses'] = zeek_subprocesses
            systemd_info_dict.update({
                'stdout': '\n'.join(textwrap.wrap(systemd_info.out, 150, fix_sentence_endings=True)),
                'stderr': '\n'.join(textwrap.wrap(systemd_info.err, 150, fix_sentence_endings=True))
            })
        else:
            zeek_status['subprocess_count'] = len(zeek_subprocesses)
        if self.log_path:
            zeek_status.update({'logs': self.log_path})
        zeek_status['info'] = systemd_info_dict
        if self.pretty_print_status:
            status_tbl = [
                [
                    'Service', self.name,
                ]
            ]
            if zeek_status['running']:
                status_tbl.append([
                    'Running', '✅'
                ])
            else:
                status_tbl.append([
                    'Running', '❌'
                ])
            if self.verbose:
                for sp in zeek_subprocesses:
                    status_tbl.append(
                        [
                            sp['process_name'], '{}'.format(sp['pid'])
                        ]
                    )
            else:
                status_tbl.append(['Subprocesses', len(zeek_subprocesses)])

            if zeek_status['info'].get('command'):
                status_tbl.append([
                    'Command', zeek_status['info'].get('command')
                ])
            if zeek_status['info'].get('exit_code'):
                status_tbl.append([
                    'Exit Code', zeek_status['info'].get('exit_code')
                ])
            if zeek_status['info'].get('stdout'):
                status_tbl.append([
                    'Stdout', zeek_status['info'].get('stdout')
                ])
            if zeek_status['info'].get('stderr'):
                status_tbl.append([
                    'Stderr', zeek_status['info'].get('stderr')
                ])
            return tabulate.tabulate(status_tbl, tablefmt='fancy_grid')

        return zeek_status


def start(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).start()


def stop(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).stop()


def restart(stdout=True, verbose=False, pretty_print_status=False):
    ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).restart()


def status(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()


