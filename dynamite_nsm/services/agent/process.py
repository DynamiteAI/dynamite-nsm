import logging
from typing import Dict, Optional, Union

import tabulate

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.zeek import process as zeek_process
from dynamite_nsm.services.filebeat import process as filebeat_process
from dynamite_nsm.services.suricata import process as suricata_process

from dynamite_nsm.services.zeek import profile as zeek_profile
from dynamite_nsm.services.filebeat import profile as filebeat_profile
from dynamite_nsm.services.suricata import profile as suricata_profile


class ProcessManager:
    """
    Agent Process Manager
    """

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Agent Processes
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If enabled, status will be printed in a tabulated style
        Returns:
            None
        """
        self.stdout = stdout
        self.verbose = verbose
        self.pretty_print_status = pretty_print_status
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('agent.process', level=log_level, stdout=stdout)

    def start(self) -> bool:
        """Start agent processes
        Returns:
            True, if successful
        """
        filebeat_res, suricata_res, zeek_res = True, True, True
        if not filebeat_profile.ProcessProfiler().is_installed():
            self.logger.error('You must install Filebeat to run this command.')
            return False
        filebeat_res = filebeat_process.ProcessManager().start()
        if suricata_profile.ProcessProfiler().is_installed():
            suricata_res = suricata_process.ProcessManager().start()
        if zeek_profile.ProcessProfiler().is_installed():
            zeek_res = zeek_process.ProcessManager().start()
        return filebeat_res and zeek_res and suricata_res

    def stop(self) -> bool:
        """Stop agent processes
        Returns:
            True, if successful
        """
        filebeat_res, suricata_res, zeek_res = True, True, True
        if not filebeat_profile.ProcessProfiler().is_installed():
            self.logger.error('You must install Filebeat to run this command.')
            return False
        filebeat_res = filebeat_process.ProcessManager().stop()
        if suricata_profile.ProcessProfiler().is_installed():
            suricata_res = suricata_process.ProcessManager().stop()
        if zeek_profile.ProcessProfiler().is_installed():
            zeek_res = zeek_process.ProcessManager().stop()
        return filebeat_res and zeek_res and suricata_res

    def status(self) -> Optional[Union[Dict, str]]:
        """Get the status of a processes
        Returns:
            A dictionary containing process status or a tabulated string if `pretty_print` is True.
        """
        if not filebeat_profile.ProcessProfiler().is_installed():
            self.logger.error('You must install filebeat to run this command.')
            return None
        agent_status = {}
        filebeat_status, zeek_status, suricata_status = {}, {}, {}
        filebeat_status = filebeat_process.ProcessManager().status()
        agent_status.update({'filebeat': {'running': filebeat_status.get('running'),
                                          'enabled_on_startup': filebeat_status.get('enabled_on_startup')}})
        if zeek_profile.ProcessProfiler().is_installed():
            zeek_status = zeek_process.ProcessManager().status()
            agent_status.update({'zeek': {'running': zeek_status.get('running'),
                                          'enabled_on_startup': zeek_status.get('enabled_on_startup')}})
        if suricata_profile.ProcessProfiler().is_installed():
            suricata_status = suricata_process.ProcessManager().status()
            agent_status.update({'suricata': {'running': suricata_status.get('running'),
                                              'enabled_on_startup': suricata_status.get('enabled_on_startup')}})
        if self.pretty_print_status:
            colorize = utilities.PrintDecorations.colorize
            child_services = [
                ['Service', 'Running', 'Enabled on Startup'],
                ['filebeat',
                 colorize('yes', 'green') if filebeat_status.get('running') else colorize('no', 'red'),
                 colorize('yes', 'green') if filebeat_status.get('enabled_on_startup') else colorize('no', 'red')
                 ]
            ]
            if zeek_status:
                child_services.append(
                    ['zeek', colorize('yes', 'green') if zeek_status.get('running') else colorize('no', 'red'),
                     colorize('yes', 'green') if zeek_status.get('enabled_on_startup') else colorize('no', 'red')]
                )
            if suricata_status:
                child_services.append(
                    ['suricata', colorize('yes', 'green') if zeek_status.get('running') else colorize('no', 'red'),
                     colorize('yes', 'green') if zeek_status.get('enabled_on_startup') else colorize('no', 'red')]
                )

            return tabulate.tabulate(child_services, tablefmt='fancy_grid')
        return agent_status

    def restart(self) -> bool:
        return self.stop() and self.start()
