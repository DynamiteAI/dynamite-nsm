import os
import logging

from dynamite_nsm import const
from dynamite_nsm.logger import get_logger
from dynamite_nsm.components.base import execution_strategy
from dynamite_nsm.services.kibana import config, install, process
from dynamite_nsm.utilities import check_socket, prompt_input


def log_message(msg, level=logging.INFO, stdout=True, verbose=False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('KIBANA_CMP', level=log_level, stdout=stdout)
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


def remove_kibana_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.KIBANA_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def check_elasticsearch_target(host, port, perform_check=True):
    if not perform_check:
        return
    if not check_socket(host, port):
        print("\n\033[93m[-] ElasticSearch does not appear to be started on: {}:{}.\033[0m".format(host, port))
        if str(prompt_input('\033[93m[?] Continue? [y|N]:\033[0m ')).lower() != 'y':
            exit(0)
    return


class KibanaChangePasswordStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to reset kibana password
    """

    def __init__(self, new_password, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name='kibana_change_password',
            strategy_description="Change the password for authenticating Kibana to ElasticSearch.",
        )
        self.add_function(func=config.change_kibana_elasticsearch_password, argument_dict={
            'password': str(new_password),
            'prompt_user': bool(prompt_user),
            'stdout': bool(stdout),
            'verbose': bool(verbose),
        })
        self.add_function(func=log_message,
                          argument_dict={'msg': 'Kibana password changed successfully!', 'stdout': bool(stdout),
                                         'verbose': bool(verbose)})


class KibanaInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install kibana
    """

    def __init__(self, listen_address, listen_port, elasticsearch_host, elasticsearch_port, elasticsearch_password,
                 check_elasticsearch_connection, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="kibana_install",
            strategy_description="Install Kibana with Dynamite Analytic views and connect to ElasticSearch.",
            functions=(
                check_elasticsearch_target,
                remove_kibana_tar_archive,
                install.install_kibana,
                process.stop,
                log_message,
                log_message
            ),
            arguments=(
                # check_elasticsearch_target
                {
                    "perform_check": bool(check_elasticsearch_connection),
                    "host": str(elasticsearch_host),
                    "port": int(elasticsearch_port)
                },
                # remove_kibana_tar_archive
                {},
                # install.install_kibana
                {
                    "configuration_directory": "/etc/dynamite/kibana/",
                    "install_directory": "/opt/dynamite/kibana/",
                    "log_directory": "/var/log/dynamite/kibana/",
                    "host": str(listen_address),
                    "port": int(listen_port),
                    "elasticsearch_host": str(elasticsearch_host),
                    "elasticsearch_port": int(elasticsearch_port),
                    "elasticsearch_password": str(elasticsearch_password),
                    "create_dynamite_user": True,
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },

                # process.stop
                {
                    "stdout": False
                },

                # log_message
                {
                    "msg": '*** Kibana installed successfully. ***',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },
                # log_message
                {
                    "msg": 'Next, Start your cluster: '
                           '\'dynamite kibana start\'. It will be available at: \033[4m{}:{}\033[0m once started.'
                           ''.format(listen_address, listen_port),
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


class KibanaUninstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to uninstall kibana
    """

    def __init__(self, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="kibana_uninstall",
            strategy_description="Uninstall Kibana.",
            functions=(
                install.uninstall_kibana,
                log_message
            ),
            arguments=(
                # install.uninstall_kibana
                {
                    'prompt_user': bool(prompt_user),
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },

                # log_message
                {
                    "msg": '*** Kibana uninstalled successfully. ***',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },
            ),
            return_formats=(
                None,
                None
            )
        )


class KibanaProcessStartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to start kibana
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="kibana_start",
            strategy_description="Start Kibana process.",
            functions=(
                process.start,
            ),
            arguments=(
                # process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },
            ),
            return_formats=(
                None,
            )

        )
        if status:
            self.add_function(process.status, {}, return_format="json")


class KibanaProcessStopStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to stop kibana
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="kibana_stop",
            strategy_description="Stop Kibana process.",
            functions=(
                process.stop,
            ),
            arguments=(
                # process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },
            ),
            return_formats=(
                None,
            )

        )
        if status:
            self.add_function(process.status, {}, return_format="json")


class KibanaProcessRestartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to restart kibana
    """

    def __init__(self, stdout, verbose, status):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="kibana_restart",
            strategy_description="Restart Kibana process.",
            functions=(
                process.stop,
                process.start,
            ),
            arguments=(
                # process.stop
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },

                # process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                }
            ),
            return_formats=(
                None,
                None
            )
        )
        if status:
            self.add_function(process.status, {}, return_format="json")


class KibanaProcessStatusStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to get status of kibana
    """

    def __init__(self):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="kibana_status",
            strategy_description="Get the status of the Kibana process.",
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
    kb_install_strategy = KibanaInstallStrategy(
        listen_address="0.0.0.0",
        listen_port=5601,
        elasticsearch_host="localhost",
        elasticsearch_port=9200,
        elasticsearch_password="changeme",
        check_elasticsearch_connection=False,
        stdout=True,
        verbose=True
    )
    kb_install_strategy.execute_strategy()


def run_uninstall_strategy():
    kb_uninstall_strategy = KibanaUninstallStrategy(
        prompt_user=False,
        stdout=True,
        verbose=True
    )
    kb_uninstall_strategy.execute_strategy()


def run_process_start_strategy():
    kb_start_strategy = KibanaProcessStartStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    kb_start_strategy.execute_strategy()


def run_process_stop_strategy():
    kb_stop_strategy = KibanaProcessStopStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    kb_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    kb_restart_strategy = KibanaProcessRestartStrategy(
        stdout=True,
        verbose=True,
        status=True
    )
    kb_restart_strategy.execute_strategy()


def run_process_status_strategy():
    kb_status_strategy = KibanaProcessStatusStrategy()
    kb_status_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    run_process_start_strategy()
    run_process_stop_strategy()
    run_process_restart_strategy()
    run_process_status_strategy()
    run_uninstall_strategy()
    pass
