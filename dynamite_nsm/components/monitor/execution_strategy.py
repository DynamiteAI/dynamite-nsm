import os
import sys
import logging

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.components.base import execution_strategy
from dynamite_nsm.services.kibana import config as kb_config
from dynamite_nsm.services.kibana import install as kb_install
from dynamite_nsm.services.kibana import process as kb_process
from dynamite_nsm.services.kibana import profile as kb_profile
from dynamite_nsm.services.logstash import config as ls_config
from dynamite_nsm.services.logstash import install as ls_install
from dynamite_nsm.services.logstash import process as ls_process
from dynamite_nsm.services.logstash import profile as ls_profile
from dynamite_nsm.services.elasticsearch import config as es_config
from dynamite_nsm.services.elasticsearch import install as es_install
from dynamite_nsm.services.elasticsearch import process as es_process
from dynamite_nsm.services.elasticsearch import profile as es_profile

from dynamite_nsm.utilities import prompt_input


def log_message(msg, level=logging.INFO, stdout=True, verbose=False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('MONITOR_CMP', level=log_level, stdout=stdout)
    if level == logging.DEBUG:
        logger.debug(msg)
    elif level == logging.INFO:
        logger.info(msg)
    elif level == logging.WARNING:
        logger.warning(msg)
    elif level == logging.ERROR:
        logger.error(msg)


def print_message(msg):
    print(msg)


def remove_elasticsearch_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def remove_logstash_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.LOGSTASH_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def remove_kibana_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.KIBANA_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def prompt_monitor_uninstall(prompt_user=True, stdout=True):
    if prompt_user:
        sys.stderr.write(
            '\n\033[93m[-] WARNING! Removing Monitor Will Delete All Saved Network Events and Corresponding '
            'Visualisations.\033[0m\n')
        resp = prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        while resp not in ['', 'no', 'yes']:
            resp = prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)


def get_monitor_status():
    return (
        dict(
            elasticsearch=es_process.status(),
            logstash=ls_process.status(),
            kibana=kb_process.status()
        )
    )


class MonitorChangePasswordStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to change all passwords on the monitor
    """

    def __init__(self, old_password, new_password, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="monitor_change_password",
            strategy_description="Change the password for all monitor components.",
        )
        if es_profile.ProcessProfiler().is_installed:
            self.add_function(func=es_config.change_elasticsearch_password, argument_dict={
                'old_password': str(old_password),
                'password': str(new_password),
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        if ls_profile.ProcessProfiler().is_installed:
            self.add_function(func=ls_config.change_logstash_elasticsearch_password, argument_dict={
                'password': str(new_password),
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        if kb_profile.ProcessProfiler().is_installed:
            self.add_function(func=kb_config.change_kibana_elasticsearch_password, argument_dict={
                'password': str(new_password),
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })

        self.add_function(func=log_message,
                          argument_dict={'msg': 'Monitor passwords changed successfully!', 'stdout': bool(stdout),
                                         'verbose': bool(verbose)})


class MonitorInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install the monitor
    """

    def __init__(self, logstash_listen_address, kibana_listen_address, kibana_listen_port, elasticsearch_host,
                 elasticsearch_port, elasticsearch_password, elasticsearch_heap_size_gigs, logstash_heap_size_gigs,
                 install_jdk, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="monitor_install",
            strategy_description="Install ElasticSearch, LogStash, and Kibana on the same instance.",
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

        self.add_function(func=remove_elasticsearch_tar_archive, argument_dict={}, return_format=None)

        self.add_function(func=remove_logstash_tar_archive, argument_dict={}, return_format=None)

        self.add_function(func=remove_kibana_tar_archive, argument_dict={}, return_format=None)

        if not es_profile.ProcessProfiler().is_installed:
            self.add_function(func=es_install.install_elasticsearch, argument_dict={
                "configuration_directory": "/etc/dynamite/elasticsearch/",
                "install_directory": "/opt/dynamite/elasticsearch/",
                "log_directory": "/var/log/dynamite/elasticsearch/",
                "password": str(elasticsearch_password),
                "heap_size_gigs": int(elasticsearch_heap_size_gigs),
                "install_jdk": bool(install_jdk),
                "create_dynamite_user": True,
                "stdout": bool(stdout),
                "verbose": bool(verbose)
            }, return_format=None)
        else:
            self.add_function(func=log_message, argument_dict={
                "msg": 'Skipping ElasticSearch installation; already installed.',
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            }, return_format=None)

        self.add_function(func=es_process.start, argument_dict={
            "stdout": False
        }, return_format=None)

        if not ls_profile.ProcessProfiler().is_installed:
            self.add_function(func=ls_install.install_logstash, argument_dict={
                "configuration_directory": "/etc/dynamite/logstash/",
                "install_directory": "/opt/dynamite/logstash/",
                "log_directory": "/var/log/dynamite/logstash/",
                "host": str(logstash_listen_address),
                "elasticsearch_host": str(elasticsearch_host),
                "elasticsearch_port": int(elasticsearch_port),
                "elasticsearch_password": str(elasticsearch_password),
                "heap_size_gigs": int(logstash_heap_size_gigs),
                "install_jdk": False,
                "create_dynamite_user": False,
                "stdout": bool(stdout),
                "verbose": bool(verbose)
            }, return_format=None)
        else:
            self.add_function(func=log_message, argument_dict={
                "msg": 'Skipping LogStash installation; already installed.',
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            }, return_format=None)

        if not kb_profile.ProcessProfiler().is_installed:
            self.add_function(func=kb_install.install_kibana, argument_dict={
                "configuration_directory": "/etc/dynamite/kibana/",
                "install_directory": "/opt/dynamite/kibana/",
                "log_directory": "/var/log/dynamite/kibana/",
                "host": str(kibana_listen_address),
                "port": int(kibana_listen_port),
                "elasticsearch_host": str(elasticsearch_host),
                "elasticsearch_port": int(elasticsearch_port),
                "elasticsearch_password": str(elasticsearch_password),
                "create_dynamite_user": True,
                "stdout": bool(stdout),
                "verbose": bool(verbose)
            }, return_format=None)
        else:
            self.add_function(func=log_message, argument_dict={
                "msg": 'Skipping Kibana installation; already installed.',
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            }, return_format=None)

        self.add_function(func=kb_process.stop, argument_dict={
            "stdout": False
        }, return_format=None)

        self.add_function(func=es_process.stop, argument_dict={
            "stdout": False
        }, return_format=None)

        self.add_function(func=log_message, argument_dict={
            "msg": '*** Monitor installed successfully. ***',
            'stdout': bool(stdout),
            'verbose': bool(verbose)
        }, return_format=None)

        self.add_function(func=log_message, argument_dict={
            "msg": 'Next, Start your monitor: '
                   '\'dynamite monitor start\'. It will be available at: \033[4m{}:{}\033[0m once started.'
                   ''.format(kibana_listen_address, kibana_listen_port),
            'stdout': bool(stdout),
            'verbose': bool(verbose)
        }, return_format=None)


class MonitorUninstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to uninstall the monitor
    """

    def __init__(self, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="monitor_uninstall",
            strategy_description="Uninstall Monitor.",
            functions=(
                utilities.create_dynamite_environment_file,
                prompt_monitor_uninstall,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},

                # prompt_user
                {
                    "prompt_user": bool(prompt_user),
                    "stdout": bool(stdout)
                },
            ),
            return_formats=(
                None,
                None
            )
        )
        if kb_profile.ProcessProfiler().is_installed:
            self.add_function(func=kb_install.uninstall_kibana, argument_dict={
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        if ls_profile.ProcessProfiler().is_installed:
            self.add_function(func=ls_install.uninstall_logstash, argument_dict={
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })
        if es_profile.ProcessProfiler().is_installed:
            self.add_function(func=es_install.uninstall_elasticsearch, argument_dict={
                'prompt_user': False,
                'stdout': bool(stdout),
                'verbose': bool(verbose)
            })

        self.add_function(func=log_message, argument_dict={
            "msg": '*** Monitor uninstalled successfully. ***',
            'stdout': bool(stdout),
            'verbose': bool(verbose)
        })


class MonitorProcessStartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to start the monitor
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="monitor_start",
            strategy_description="Start Monitor processes.",
            functions=(
                utilities.create_dynamite_environment_file,
                es_process.start,
                ls_process.start,
                kb_process.start
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # es_process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # ls_process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # kb_process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                }
            ),
            return_formats=(
                None,
                None,
                None,
                None
            )
        )
        if status:
            self.add_function(get_monitor_status, {}, return_format="json")


class MonitorProcessStopStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to stop the monitor
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="monitor_stop",
            strategy_description="Stop Monitor processes.",
            functions=(
                utilities.create_dynamite_environment_file,
                ls_process.stop,
                kb_process.stop,
                es_process.stop,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # ls_process.start.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # kb_process.start.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # es_process.start.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                }
            ),
            return_formats=(
                None,
                None,
                None,
                None
            )
        )
        if status:
            self.add_function(get_monitor_status, {}, return_format="json")


class MonitorProcessRestartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to restart the monitor
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="monitor_restart",
            strategy_description="Restart Monitor processes.",
            functions=(
                utilities.create_dynamite_environment_file,
                ls_process.stop,
                kb_process.stop,
                es_process.stop,
                es_process.start,
                kb_process.start,
                ls_process.start,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # ls_process.stop
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # kb_process.stop
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # es_process.stop
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # es_process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # kb_process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # ls_process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                }

            ),
            return_formats=(
                None,
                None,
                None,
                None,
                None,
                None,
                None
            )
        )
        if status:
            self.add_function(get_monitor_status, {}, return_format="json")


class MonitorProcessStatusStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to get the status of the monitor
    """

    def __init__(self):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="monitor_status",
            strategy_description="Get the status of the Monitor processes.",
            functions=(
                utilities.create_dynamite_environment_file,
                get_monitor_status,
            ),
            arguments=(
                # utilities.create_dynamite_environment_file
                {},
                # get_monitor_status
                {},
            ),
            return_formats=(
                None,
                'json',
            )
        )


# Test Functions

def run_install_strategy():
    mon_install_strategy = MonitorInstallStrategy(
        logstash_listen_address="0.0.0.0",
        kibana_listen_address="0.0.0.0",
        kibana_listen_port=5601,
        elasticsearch_host="localhost",
        elasticsearch_port=9200,
        elasticsearch_password="changeme",
        elasticsearch_heap_size_gigs=4,
        logstash_heap_size_gigs=4,
        install_jdk=True,
        stdout=True,
        verbose=True
    )
    mon_install_strategy.execute_strategy()


def run_uninstall_strategy():
    mon_uninstall_strategy = MonitorUninstallStrategy(
        stdout=True,
        verbose=True,
        prompt_user=False
    )
    mon_uninstall_strategy.execute_strategy()


def run_process_start_strategy():
    mon_start_strategy = MonitorProcessStartStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    mon_start_strategy.execute_strategy()


def run_process_stop_strategy():
    mon_stop_strategy = MonitorProcessStopStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    mon_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    mon_restart_strategy = MonitorProcessRestartStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    mon_restart_strategy.execute_strategy()


def run_process_status_strategy():
    mon_status_strategy = MonitorProcessStatusStrategy()
    mon_status_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    run_process_start_strategy()
    run_process_stop_strategy()
    run_process_restart_strategy()
    run_process_status_strategy()
    run_uninstall_strategy()
    pass
