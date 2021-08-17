import os
import re
import subprocess
from typing import Dict, Optional, Union

import tabulate

from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm.services.zeek import profile as zeek_profile


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Zeek processes and sub-processes
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If true, status will be printed in a tabular form
        """
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('ZEEK_HOME')
        process.BaseProcessManager.__init__(self, 'zeek.service', 'zeek.process', log_path=None,
                                            stdout=stdout, verbose=verbose,
                                            pretty_print_status=pretty_print_status)

        if not zeek_profile.ProcessProfiler().is_installed():
            raise general_exceptions.CallProcessError("Zeek is not installed.")

    def status(self) -> Union[Dict, str]:
        """
        Get the status of Zeek processes

        Returns:
            A dictionary or string depending on the value of self.pretty_print_status

        """
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
            'running': systemd_info.exit == 0,
            'enabled_on_startup': self.sysctl.is_enabled(self.systemd_service)
        }
        zeek_subprocesses = []
        for line in raw_output.split('\n')[1:]:
            tokenized_line = re.findall(r'\S+', line)
            if len(tokenized_line) == 8:
                name, _type, host, status, pid, _, _, _ = tokenized_line
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
                'stdout': utilities.wrap_text(systemd_info.out),
                'stderr': utilities.wrap_text(systemd_info.err)
            })
        else:
            zeek_status['subprocess_count'] = len(zeek_subprocesses)
        if self.log_path:
            zeek_status.update({'logs': self.log_path})
        zeek_status['info'] = systemd_info_dict
        if self.pretty_print_status:
            colorize = utilities.PrintDecorations.colorize
            status_tbl = [[
                'Service', self.name,
            ], ['Running', colorize('yes', 'green') if zeek_status['running'] else colorize('no', 'red')],
                ['Enabled on Startup',
                 colorize('yes', 'green') if zeek_status['enabled_on_startup'] else colorize('no', 'red')]]
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
                    'STDOUT', zeek_status['info'].get('stdout')
                ])
            if zeek_status['info'].get('stderr'):
                status_tbl.append([
                    'STDERR', zeek_status['info'].get('stderr')
                ])
            return tabulate.tabulate(status_tbl, tablefmt='fancy_grid')
        return zeek_status
