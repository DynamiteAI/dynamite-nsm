import sys
import logging

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.lab import install, process, profile
from dynamite_nsm.components.base import execution_strategy
from dynamite_nsm.utilities import check_socket, prompt_input


def log_message(msg, level=logging.INFO, stdout=True, verbose=False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('LAB_CMP', level=log_level, stdout=stdout)
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


def check_elasticsearch_target(host, port, perform_check=True):
    if not perform_check:
        return
    if not check_socket(host, port):
        print("\n\033[93m[-] ElasticSearch does not appear to be started on: {}:{}.\033[0m".format(host, port))
        if str(prompt_input('\033[93m[?] Continue? [y|N]:\033[0m ')).lower() != 'y':
            exit(0)
    return


class LabInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install DynamiteLab
    """

    def __init__(self, jupyterhub_host, jupyterhub_password, elasticsearch_host, elasticsearch_port,
                 elasticsearch_password, check_elasticsearch_connection, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="lab_install",
            strategy_description="Install DynamiteLab (DynamiteSDK and JupyterHub).",
            functions=(
                utilities.print_dynamite_lab_art,
                check_elasticsearch_target,
                install.install_dynamite_lab,
                process.stop,
                log_message,
                log_message
            ),
            arguments=(
                # utilities.print_dynamite_lab_art
                {},
                # check_elasticsearch_target
                {
                    "perform_check": bool(check_elasticsearch_connection),
                    "host": str(elasticsearch_host),
                    "port": int(elasticsearch_port)
                },
                # install.install_dynamite_lab
                {
                    "configuration_directory": "/etc/dynamite/dynamite_sdk/",
                    "notebook_home": "/etc/dynamite/notebooks",
                    "jupyterhub_host": jupyterhub_host,
                    "jupyterhub_password": str(jupyterhub_password),
                    "elasticsearch_host": str(elasticsearch_host),
                    "elasticsearch_port": int(elasticsearch_port),
                    "elasticsearch_password": str(elasticsearch_password),
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },

                # process.stop
                {
                    "stdout": False
                },

                # log_message
                {
                    "msg": '*** Lab installed successfully. ***'
                },
                # log_message
                {
                    "msg": 'Next, Start DynamiteLab: '
                           '\'dynamite lab start\'. It will be available at: \033[4m{}:{}\033[0m once started.'.format(
                        jupyterhub_host, 8000),
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                }
            ),
            return_formats=(
                None,
                None,
                None,
                None,
                None,
                None
            ))


class LabUninstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to uninstall DynamiteLab
    """

    def __init__(self, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="lab_uninstall",
            strategy_description="Uninstall Lab.",
            functions=(
                install.uninstall_dynamite_lab,
                log_message
            ),
            arguments=(
                # install.uninstall_dynamite_lab
                {
                    'prompt_user': bool(prompt_user),
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },

                # log_message
                {
                    "msg": '*** Lab uninstalled successfully. ***',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },
            ),
            return_formats=(
                None,
                None
            )
        )
        if profile.ProcessProfiler().is_installed:
            self.add_function(
                func=install.uninstall_dynamite_lab,
                argument_dict={
                    'prompt_user': bool(prompt_user),
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                }
            )
            self.add_function(
                func=log_message,
                argument_dict={
                    "msg": '*** Lab uninstalled successfully. ***',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                }
            )


class LabProcessStartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to start DynamiteLab
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="lab_start",
            strategy_description="Start Lab process.",
        )
        if profile.ProcessProfiler().is_installed:
            self.add_function(
                func=process.start,
                argument_dict={
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },
            )
        if status:
            self.add_function(process.status, {}, return_format="json")


class LabProcessStopStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to stop DynamiteLab
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="lab_stop",
            strategy_description="Stop Lab process.",
        )
        if profile.ProcessProfiler().is_installed:
            self.add_function(
                func=process.stop,
                argument_dict={
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },
            )
        if status:
            self.add_function(process.status, {}, return_format="json")


class LabProcessRestartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to restart kibana
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="lab_restart",
            strategy_description="Restart Lab process.",
        )
        if profile.ProcessProfiler().is_installed:
            self.add_function(
                func=process.stop,
                argument_dict={
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },
            )
            self.add_function(
                func=process.start,
                argument_dict={
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },
            )
        if status:
            self.add_function(process.status, {}, return_format="json")


class LabProcessStatusStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to get status of kibana
    """

    def __init__(self):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="lab_status",
            strategy_description="Get the status of the Lab process.",
            functions=(
                process.status,
            ),
            arguments=(
                # process.status
                {},
            ),
            return_formats=(
                'json',
            )
        )


# Test Functions


def run_install_strategy():
    lab_install_strategy = LabInstallStrategy(
        jupyterhub_host='localhost',
        jupyterhub_password='changeme',
        elasticsearch_host="localhost",
        elasticsearch_port=9200,
        elasticsearch_password="changeme",
        check_elasticsearch_connection=False,
        stdout=True,
        verbose=True
    )
    lab_install_strategy.execute_strategy()


def run_uninstall_strategy():
    lab_uninstall_strategy = LabUninstallStrategy(
        prompt_user=False,
        stdout=True,
        verbose=True
    )
    lab_uninstall_strategy.execute_strategy()


def run_process_start_strategy():
    lab_start_strategy = LabProcessStartStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    lab_start_strategy.execute_strategy()


def run_process_stop_strategy():
    lab_stop_strategy = LabProcessStopStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    lab_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    lab_restart_strategy = LabProcessRestartStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    lab_restart_strategy.execute_strategy()


def run_process_status_strategy():
    lab_status_strategy = LabProcessStatusStrategy()
    lab_status_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    run_process_start_strategy()
    run_process_stop_strategy()
    run_process_restart_strategy()
    run_process_status_strategy()
    run_uninstall_strategy()
    pass
