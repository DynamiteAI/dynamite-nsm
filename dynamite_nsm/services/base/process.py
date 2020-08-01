import os
import logging

from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger


class BaseProcessManager:

    def __init__(self, systemd_service, log_path=None, pid_file=None, stdout=True, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('BASESVC', level=log_level, stdout=stdout)

        self.pid = None

        self.systemd_service = systemd_service
        self.log_path = log_path
        self.pid_file = pid_file
        self.stdout = stdout
        self.verbose = verbose
        self.sysctl = systemctl.SystemCtl()
        if pid_file:
            self.pid = self._get_pid(pid_file)

    @staticmethod
    def _get_pid(pid_file):
        pid = None
        h, t = os.path.split(pid_file)
        utilities.makedirs(h, exist_ok=True)
        try:
            with open(pid_file) as pid_f:
                pid = int(pid_f.read())
        except (IOError, ValueError):
            pass
        return pid

    def start(self):
        self.logger.info('Attempting to start {}'.format(self.systemd_service))
        return self.sysctl.start(self.systemd_service)

    def stop(self):
        self.logger.info('Attempting to stop {}'.format(self.systemd_service))
        return self.sysctl.stop(self.systemd_service)

    def status(self):
        if self.pid_file:
            self.pid = self._get_pid(self.pid_file)
        return {
            'pid': self.pid,
            'running': utilities.check_pid(self.pid),
            'logs': self.log_path
        }

    def restart(self):
        self.logger.info('Attempting to restart {}'.format(self.systemd_service))
        return self.sysctl.restart(self.systemd_service)
