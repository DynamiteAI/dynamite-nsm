import logging
import os
from typing import Dict, Optional, Union

import tabulate

from dynamite_nsm import exceptions
from dynamite_nsm import const, utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.base import systemctl


class BaseProcessManager:
    """
    A Systemd wrapper for process management
    """

    def __init__(self, systemd_service: str, name: str, log_path: Optional[str] = None,
                 create_pid_file: Optional[bool] = False,
                 stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage a service process
        Args:
            systemd_service: The name of the systemd.service file
            name: The name of the process manager
            log_path: The path to where the process logs
            create_pid_file: If true will attempt to create a PID file
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If enabled, status will be printed in a tabulated style
        """
        if not utilities.is_setup():
            raise exceptions.DynamiteNotSetupError()
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger(name, level=log_level, stdout=stdout)
        self.pid_file = None
        self.pid = None
        self.systemd_service = systemd_service
        self.name = name
        self.log_path = log_path
        if create_pid_file:
            self.pid_file = f'{const.PID_PATH}/{name}.pid'
        self.stdout = stdout
        self.verbose = verbose
        self.pretty_print_status = pretty_print_status
        self.sysctl = systemctl.SystemCtl()
        if create_pid_file:
            self.pid = self._get_pid(self.pid_file)

    @staticmethod
    def _get_pid(pid_file: str) -> int:
        pid = None
        h, t = os.path.split(pid_file)
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
        """Disable process
        Returns:
            True, if successfully disabled
        """
        self.logger.info('Disabling on startup: {}'.format(self.systemd_service))
        return self.sysctl.disable(self.systemd_service, daemon_reload=True)

    def enable(self) -> bool:
        """Enabled process
        Returns:
            True, if successfully enabled
        """
        self.logger.info('Enabling on startup: {}'.format(self.systemd_service))
        return self.sysctl.enable(self.systemd_service, daemon_reload=True)

    def start(self) -> bool:
        """Start process
        Returns:
            True, if successfully started
        """
        self.logger.info('Attempting to start {}'.format(self.systemd_service))
        return self.sysctl.start(self.systemd_service)

    def stop(self) -> bool:
        """Stop process
        Returns:
            True, if successfully stopped
        """
        self.logger.info('Attempting to stop {}'.format(self.systemd_service))
        return self.sysctl.stop(self.systemd_service)

    def status(self) -> Union[Dict, str]:
        """Get the status of a process
        Returns:
            A dictionary containing process status or a tabulated string if `pretty_print` is True.
        """
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
            colorize = utilities.PrintDecorations.colorize
            status_tbl = [[
                'Service', self.name,
            ], ['Running', colorize('yes', 'green') if status['running'] else colorize('no', 'red')],
                ['Enabled on Startup',
                 colorize('yes', 'green') if status['enabled_on_startup'] else colorize('no', 'red')]]
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
        """Restart Process
        Returns:
            True, if the process was restarted
        """
        self.logger.info('Attempting to restart {}'.format(self.systemd_service))
        return self.sysctl.restart(self.systemd_service)
