import logging
from typing import Dict, Optional, Union

import tabulate

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.elasticsearch import process as elasticsearch_process
from dynamite_nsm.services.kibana import process as kibana_process
from dynamite_nsm.services.logstash import process as logstash_process

from dynamite_nsm.services.elasticsearch import profile as elasticsearch_profile
from dynamite_nsm.services.kibana import profile as kibana_profile
from dynamite_nsm.services.logstash import profile as logstash_profile


class ProcessManager:
    """
    Monitor Process Manager
    """

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Monitor Process
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
        """Start the monitor services
        Returns:
            True, if successfully started
        """
        kibana_res, logstash_res, elasticsearch_res = True, True, True
        if not elasticsearch_profile.ProcessProfiler().is_installed():
            self.logger.error('You must install kibana to run this command.')
            return False
        elasticsearch_res = elasticsearch_process.ProcessManager().start()
        if logstash_profile.ProcessProfiler().is_installed():
            logstash_res = logstash_process.ProcessManager().start()
        if kibana_profile.ProcessProfiler().is_installed():
            kibana_res = kibana_process.ProcessManager().start()
        return kibana_res and elasticsearch_res and logstash_res

    def stop(self) -> bool:
        """Stop the monitor services
        Returns:
            True, if successfully stopped
        """
        kibana_res, logstash_res, elasticsearch_res = True, True, True
        if not elasticsearch_profile.ProcessProfiler().is_installed():
            self.logger.error('You must install kibana to run this command.')
            return False
        elasticsearch_res = elasticsearch_process.ProcessManager().stop()
        if logstash_profile.ProcessProfiler().is_installed():
            logstash_res = logstash_process.ProcessManager().stop()
        if kibana_profile.ProcessProfiler().is_installed():
            kibana_res = kibana_process.ProcessManager().stop()
        return kibana_res and elasticsearch_res and logstash_res

    def status(self) -> Optional[Union[Dict, str]]:
        """Get the statuses of monitor services
        Returns:
            The statuses of monitor services
        """
        agent_status = {}
        kibana_status, elasticsearch_status, logstash_status = {}, {}, {}
        if not elasticsearch_profile.ProcessProfiler().is_installed():
            self.logger.error('You must install elasticsearch to run this command.')
            return None

        elasticsearch_status = elasticsearch_process.ProcessManager().status()
        agent_status.update({'elasticsearch': {'running': elasticsearch_status.get('running'),
                                               'enabled_on_startup': elasticsearch_status.get(
                                                   'enabled_on_startup')}})
        if logstash_profile.ProcessProfiler().is_installed():
            logstash_status = logstash_process.ProcessManager().status()
            agent_status.update({'logstash': {'running': logstash_status.get('running'),
                                              'enabled_on_startup': logstash_status.get('enabled_on_startup')}})
        if kibana_profile.ProcessProfiler().is_installed():
            kibana_status = kibana_process.ProcessManager().status()
            agent_status.update({'kibana': {'running': kibana_status.get('running'),
                                            'enabled_on_startup': kibana_status.get('enabled_on_startup')}})

        if self.pretty_print_status:
            colorize = utilities.PrintDecorations.colorize
            child_services = [
                ['Service', 'Running', 'Enabled on Startup'],
                ['kibana',
                 colorize('yes', 'green') if kibana_status.get('running') else colorize('no', 'red'),
                 colorize('yes', 'green') if kibana_status.get('enabled_on_startup') else colorize('no',
                                                                                                   'red')
                 ]
            ]
            if elasticsearch_status:
                child_services.append(
                    ['elasticsearch',
                     colorize('yes', 'green') if elasticsearch_status.get('running') else colorize('no', 'red'),
                     colorize('yes', 'green') if elasticsearch_status.get('enabled_on_startup') else colorize('no',
                                                                                                              'red')]
                )
            if logstash_status:
                child_services.append(
                    ['logstash',
                     colorize('yes', 'green') if elasticsearch_status.get('running') else colorize('no', 'red'),
                     colorize('yes', 'green') if elasticsearch_status.get('enabled_on_startup') else colorize('no',
                                                                                                              'red')]
                )

            return tabulate.tabulate(child_services, tablefmt='fancy_grid')
        return agent_status

    def restart(self) -> bool:
        """Restart monitor services
        Returns:
            True, if successfully restarted
        """
        return self.stop() and self.start()
