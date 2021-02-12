import logging
import os
from typing import Dict, Optional, Union

import tabulate

from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger


class BaseProcessManager:

    def __init__(self, systemd_service: str, name: str, log_path: Optional[str] = None, pid_file: Optional[str] = None,
                 stdout: Optional[str] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger(str(name).upper(), level=log_level, stdout=stdout)

        self.pid = None
        self.systemd_service = systemd_service
        self.name = name
        self.log_path = log_path
        self.pid_file = pid_file
        self.stdout = stdout
        self.verbose = verbose
        self.pretty_print_status = pretty_print_status
        self.sysctl = systemctl.SystemCtl()
        if pid_file:
            self.pid = self._get_pid(pid_file)

    @staticmethod
    def _get_pid(pid_file: str) -> int:
        pid = None
        h, t = os.path.split(pid_file)
        utilities.makedirs(h, exist_ok=True)
        try:
            utilities.set_ownership_of_file(h)
        # PID file does not exist
        except IOError:
            pass
        # dynamite user does not exist
        except KeyError:
            pass
        try:
            with open(pid_file) as pid_f:
                pid = int(pid_f.read())
        except (IOError, ValueError):
            pass
        return pid

    def disable(self) -> bool:
        self.logger.info('Disabling on startup: {}'.format(self.systemd_service))
        return self.sysctl.disable(self.systemd_service, daemon_reload=True)

    def enable(self) -> bool:
        self.logger.info('Enabling on startup: {}'.format(self.systemd_service))
        return self.sysctl.enable(self.systemd_service, daemon_reload=True)

    def start(self) -> bool:
        self.logger.info('Attempting to start {}'.format(self.systemd_service))
        return self.sysctl.start(self.systemd_service)

    def stop(self) -> bool:
        self.logger.info('Attempting to stop {}'.format(self.systemd_service))
        return self.sysctl.stop(self.systemd_service)

    def status(self) -> Union[Dict, str]:
        if self.pid_file:
            self.pid = self._get_pid(self.pid_file)
        systemd_info = self.sysctl.status(self.systemd_service)
        info_dict = {
            'command': systemd_info.cmd,
            'exit_code': systemd_info.exit,
        }
        if self.verbose:
            info_dict.update({
                'stdout': utilities.wrap_text(systemd_info.out),
                'stderr': utilities.wrap_text(systemd_info.err)
            })
        status = {
            'running': systemd_info.exit == 0,
            'enabled_on_startup': self.sysctl.is_enabled(self.systemd_service)
        }
        if self.pid:
            status.update({'pid': self.pid})
        if self.log_path:
            status.update({'logs': self.log_path})

        status.update({'info': info_dict})
        if self.pretty_print_status:
            status_tbl = [
                [
                    'Service', self.name,
                ]
            ]
            if status['running']:
                status_tbl.append([
                    'Running', '\033[92myes\033[0m'
                ])
            else:
                status_tbl.append([
                    'Running', '\033[91mno\033[0m'
                ])
            if status.get('pid'):
                status_tbl.append([
                    'PID', status['pid']
                ])
            if status.get('logs'):
                status_tbl.append([
                    'Logs', status['logs']
                ])
            if status['info'].get('command'):
                status_tbl.append([
                    'Command', status['info'].get('command')
                ])
            if status['info'].get('exit_code'):
                status_tbl.append([
                    'Exit Code', status['info'].get('exit_code')
                ])
            if status['info'].get('stdout'):
                status_tbl.append([
                    'STDOUT', status['info'].get('stdout')
                ])
            if status['info'].get('stderr'):
                status_tbl.append([
                    'STDERR', status['info'].get('stderr')
                ])
            return tabulate.tabulate(status_tbl, tablefmt='fancy_grid')
        return status

    def restart(self) -> bool:
        self.logger.info('Attempting to restart {}'.format(self.systemd_service))
        return self.sysctl.restart(self.systemd_service)
