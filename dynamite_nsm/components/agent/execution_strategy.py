import os
import sys
import logging

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.tuis import agent_config_selector
from dynamite_nsm.components.base import execution_strategy
from dynamite_nsm.services.zeek import install as zeek_install
from dynamite_nsm.services.zeek import process as zeek_process
from dynamite_nsm.services.zeek import profile as zeek_profile
from dynamite_nsm.services.filebeat import install as filebeat_install
from dynamite_nsm.services.filebeat import process as filebeat_process
from dynamite_nsm.services.filebeat import profile as filebeat_profile
from dynamite_nsm.services.suricata import install as suricata_install
from dynamite_nsm.services.suricata import process as suricata_process
from dynamite_nsm.services.suricata import profile as suricata_profile
from dynamite_nsm.services.suricata.oinkmaster import install as oinkmaster_install

from dynamite_nsm.utilities import prompt_input


def log_message(msg, level=logging.INFO, stdout=True, verbose=False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('AGENT_CMP', level=log_level, stdout=stdout)
    if level == logging.DEBUG:
        logger.debug(msg)
    elif level == logging.INFO:
        logger.info(msg)
    elif level == logging.WARNING:
        logger.warning(msg)
    elif level == logging.ERROR:
        logger.error(msg)


def get_agent_status(include_subprocesses=False):
    zeek_profiler = zeek_profile.ProcessProfiler()
    suricata_profiler = suricata_profile.ProcessProfiler()
    filebeat_profiler = filebeat_profile.ProcessProfiler()

    agent_status = {}
    if zeek_profiler.is_installed:
        zeek_status = zeek_process.ProcessManager().status()
        if not include_subprocesses:
            subprocess_count = len(zeek_status['SUBPROCESSES'])
            del zeek_status['SUBPROCESSES']
            zeek_status.update({
                "SUBPROCESS_COUNT": subprocess_count
            })
        agent_status.update({
            'ZEEK': zeek_status
        })
    if suricata_profiler.is_installed:
        agent_status.update({
            'SURICATA': suricata_process.ProcessManager().status()
        })
    if filebeat_profiler.is_installed:
        agent_status.update({
            'FILEBEAT': filebeat_process.ProcessManager().status()
        })
    return agent_status


def get_installed_agent_analyzers():
    zeek_profiler = zeek_profile.ProcessProfiler()
    suricata_profiler = suricata_profile.ProcessProfiler()
    filebeat_profiler = filebeat_profile.ProcessProfiler()

    agent_analyzers = []
    if zeek_profiler.is_installed:
        agent_analyzers.append('Zeek')
    if suricata_profiler.is_installed:
        agent_analyzers.append('Suricata')
    if filebeat_profiler.is_installed:
        agent_analyzers.append('Filebeat')
    return agent_analyzers


def print_message(msg):
    print(msg)


def remove_filebeat_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def remove_zeek_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.ZEEK_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def remove_suricata_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.SURICATA_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def prompt_agent_uninstall(prompt_user=True, stdout=True):
    if prompt_user:
        sys.stderr.write(
            '\n\033[93m[-] WARNING! Removing Agent Will Remove the Agent and all of it\'s installed components: {}.'
            '\033[0m\n'.format(get_installed_agent_analyzers()))
        resp = prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)


class AgentConfigStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to configure the agent
    """

    def __init__(self):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="agent_config",
            strategy_description="Configure the agent.",
            functions=(
                utilities.create_dynamite_environment_file,
                agent_config_selector.run_gui,
            ),
            arguments=(
                {},
                {},
            ),
            return_formats=(
                None,
                None,
            )
        )


class AgentInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install the agent
    """

    def __init__(self, capture_network_interfaces, targets, kafka_topic=None, kafka_username=None, kafka_password=None,
                 agent_analyzers=('zeek', 'suricata'), tag=None, stdout=True, verbose=False):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="agent_install",
            strategy_description="Install Zeek and/or Suricata along with FileBeat.",
            functions=(
                utilities.create_dynamite_environment_file,
            ),
            arguments=(
                {},
            ),
            return_formats=(
                None,
            )
        )
        if not filebeat_profile.ProcessProfiler().is_installed:
            filebeat_args = {
                'targets': list(targets),
                'kafka_topic': kafka_topic,
                'kafka_username': kafka_username,
                'kafka_password': kafka_password,
                'agent_tag': tag,
                'install_directory': '/opt/dynamite/filebeat/',
                'download_filebeat_archive': True,
                'stdout': bool(stdout)
            }
            monitor_log_paths = []
            if 'zeek' in agent_analyzers:
                monitor_log_paths.append("/opt/dynamite/zeek/logs/current/*.log")
            if 'suricata' in agent_analyzers:
                monitor_log_paths.append('/var/log/dynamite/suricata/eve.json')
            filebeat_args.update({
                'monitor_log_paths': monitor_log_paths
            })
            self.add_function(func=filebeat_install.install_filebeat, argument_dict=filebeat_args)
        else:
            self.add_function(func=log_message,
                              argument_dict={
                                  "msg": 'Skipping Filebeat installation; already installed',
                                  'stdout': bool(stdout),
                                  'verbose': bool(verbose)
                              },
                              return_format=None)
        if not zeek_profile.ProcessProfiler().is_installed and 'zeek' in agent_analyzers:
            self.add_function(func=zeek_install.install_zeek, argument_dict={
                'configuration_directory': '/etc/dynamite/zeek/',
                'install_directory': '/opt/dynamite/zeek',
                'capture_network_interfaces': list(capture_network_interfaces),
                'download_zeek_archive': True,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        else:
            self.add_function(func=log_message, argument_dict={
                "msg": 'Skipping Zeek installation.',
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            },
                              return_format=None)
        if not suricata_profile.ProcessProfiler().is_installed and 'suricata' in agent_analyzers:
            self.add_function(func=suricata_install.install_suricata, argument_dict={
                'configuration_directory': '/etc/dynamite/suricata/',
                'install_directory': '/opt/dynamite/suricata',
                'log_directory': '/var/log/dynamite/suricata/',
                'capture_network_interfaces': list(capture_network_interfaces),
                'download_suricata_archive': True,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        else:
            self.add_function(func=log_message, argument_dict={
                "msg": 'Skipping Suricata installation.',
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            },
                              return_format=None)
        self.add_function(func=log_message, argument_dict={
            "msg": '*** Agent installed successfully. ***',
            'verbose': bool(verbose)
        })
        self.add_function(func=log_message, argument_dict={
            "msg": 'Next, Start your agent: '
                   '\'dynamite agent start\'.',
            'stdout': bool(stdout),
            'verbose': bool(verbose)
        }, return_format=None)


class AgentUninstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to uninstall the agent
    """

    def __init__(self, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="agent_uninstall",
            strategy_description="Uninstall Agent.",
            functions=(
                utilities.create_dynamite_environment_file,
                prompt_agent_uninstall,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # prompt_user
                {
                    "prompt_user": bool(prompt_user),
                    "stdout": bool(stdout),
                },
            ),
            return_formats=(
                None,
                None,
            )
        )
        if filebeat_profile.ProcessProfiler().is_installed:
            self.add_function(func=filebeat_install.uninstall_filebeat, argument_dict={
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        if zeek_profile.ProcessProfiler().is_installed:
            self.add_function(func=zeek_install.uninstall_zeek, argument_dict={
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        if suricata_profile.ProcessProfiler().is_installed:
            self.add_function(func=suricata_install.uninstall_suricata, argument_dict={
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        if get_installed_agent_analyzers():
            self.add_function(func=log_message, argument_dict={
                "msg": '*** Agent uninstalled successfully. ***',
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        else:
            self.add_function(func=log_message, argument_dict={
                "msg": '*** Agent is not installed. ***',
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })


class AgentProcessStartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to start the agent
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="agent_start",
            strategy_description="Start Agent processes.",
            functions=(
                utilities.create_dynamite_environment_file,
                filebeat_process.start,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # filebeat_process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },
            ),
            return_formats=(
                None,
                None
            )

        )
        if zeek_profile.ProcessProfiler().is_installed:
            self.add_function(func=zeek_process.start, argument_dict={
                "stdout": bool(stdout),
                "verbose": bool(verbose)
            })
        if suricata_profile.ProcessProfiler().is_installed:
            self.add_function(func=suricata_process.start, argument_dict={
                "stdout": bool(stdout),
                "verbose": bool(verbose)
            })
        if status:
            self.add_function(get_agent_status, {}, return_format="json")


class AgentProcessStopStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to stop the agent
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="agent_stop",
            strategy_description="Stop Agent processes.",
            functions=(
                utilities.create_dynamite_environment_file,
                filebeat_process.stop,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # filebeat_process.stop
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
            ),
            return_formats=(
                None,
                None
            )

        )
        if zeek_profile.ProcessProfiler().is_installed:
            self.add_function(func=zeek_process.stop, argument_dict={
                "stdout": bool(stdout),
                "verbose": bool(verbose)
            })
        if suricata_profile.ProcessProfiler().is_installed:
            self.add_function(func=suricata_process.stop, argument_dict={
                "stdout": bool(stdout),
                "verbose": bool(verbose)
            })
        if status:
            self.add_function(get_agent_status, {}, return_format="json")


class AgentProcessRestartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to restart the agent
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="agent_restart",
            strategy_description="Restart Agent processes."
        )
        self.add_function(func=filebeat_process.stop, argument_dict={
            'stdout': bool(stdout), 'verbose': bool(verbose)
        })
        self.add_function(func=filebeat_process.start, argument_dict={
            'stdout': bool(stdout)
        })
        if zeek_profile.ProcessProfiler().is_installed:
            self.add_function(func=zeek_process.stop, argument_dict={
                'stdout': bool(stdout), 'verbose': bool(verbose)
            })
            self.add_function(func=zeek_process.start, argument_dict={
                'stdout': bool(stdout), 'verbose': bool(verbose)
            })
        if suricata_profile.ProcessProfiler().is_installed:
            self.add_function(func=suricata_process.stop, argument_dict={
                'stdout': bool(stdout), 'verbose': bool(verbose)
            })
            self.add_function(func=suricata_process.start, argument_dict={
                'stdout': bool(stdout), 'verbose': bool(verbose)
            })
        if status:
            self.add_function(get_agent_status, {}, return_format="json")


class AgentProcessStatusStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to get the status of the agent
    """

    def __init__(self, include_subprocesses):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="agent_status",
            strategy_description="Get the status of the Agent processes.",
            functions=(
                utilities.create_dynamite_environment_file,
                get_agent_status,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # get_agent_status
                {
                    'include_subprocesses': bool(include_subprocesses)
                },
            ),
            return_formats=(
                None,
                'json',
            )
        )


class AgentSuricataUpdateStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to update agent Suricata rules
    """

    def __init__(self):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="agent_update",
            strategy_description="Get the latest EmergingThreat signatures for Suricata.",
            functions=(
                utilities.create_dynamite_environment_file,
                oinkmaster_install.update_suricata_rules,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # oinkmaster_install.update_suricata_rules
                {}
            ),
            return_formats=(
                None,
                None
            )
        )


# Test Functions

def run_install_strategy():
    agt_install_strategy = AgentInstallStrategy(
        capture_network_interfaces=['eth0'],
        targets=['localhost:5044'],
        agent_analyzers=('zeek', 'suricata'),
        stdout=True,
        verbose=True
    )
    agt_install_strategy.execute_strategy()


def run_uninstall_strategy():
    agt_uninstall_strategy = AgentUninstallStrategy(
        prompt_user=False,
        stdout=True,
        verbose=True,
    )
    agt_uninstall_strategy.execute_strategy()


def run_process_start_strategy():
    agt_start_strategy = AgentProcessStartStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    agt_start_strategy.execute_strategy()


def run_process_stop_strategy():
    agt_stop_strategy = AgentProcessStopStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    agt_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    agt_restart_strategy = AgentProcessRestartStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    agt_restart_strategy.execute_strategy()


def run_process_status_strategy():
    agt_status_strategy = AgentProcessStatusStrategy(
        include_subprocesses=False
    )
    agt_status_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    run_process_start_strategy()
    run_process_stop_strategy()
    run_process_restart_strategy()
    run_process_status_strategy()
    run_uninstall_strategy()
    pass
