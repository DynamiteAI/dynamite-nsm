import os
import logging

from dynamite_nsm import const
from dynamite_nsm.logger import get_logger
from dynamite_nsm.components.base import execution_strategy
from dynamite_nsm.utilities import check_socket, prompt_input
from dynamite_nsm.services.logstash import config, install, process


def print_message(msg):
    print(msg)


def remove_logstash_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.LOGSTASH_ARCHIVE_NAME)
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


def log_message(msg, level=logging.INFO, stdout=True, verbose=False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('LOGSTASH_CMP', level=log_level, stdout=stdout)
    if level == logging.DEBUG:
        logger.debug(msg)
    elif level == logging.INFO:
        logger.info(msg)
    elif level == logging.WARNING:
        logger.warning(msg)
    elif level == logging.ERROR:
        logger.error(msg)
        

class LogStashChangePasswordStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to reset logstash password
    """

    def __init__(self, new_password, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name='logstash_change_password',
            strategy_description="Change the password for all LogStash ElasticSearch output configurations.",
        )
        self.add_function(func=config.change_logstash_elasticsearch_password, argument_dict={
            'password': str(new_password),
            'prompt_user': bool(prompt_user),
            'stdout': bool(stdout),
            'verbose': bool(verbose),
        })
        self.add_function(func=log_message, argument_dict={'msg': 'LogStash password changed successfully!'})


class LogstashInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install logstash
    """

    def __init__(self, listen_address, elasticsearch_host, elasticsearch_port, elasticsearch_password, heap_size_gigs,
                 install_jdk, check_elasticsearch_connection, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="logstash_install",
            strategy_description="Install and connect LogStash to ElasticSearch.",
            functions=(
                check_elasticsearch_target,
                remove_logstash_tar_archive,
                install.install_logstash,
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
                # remove_logstash_tar_archive
                {},
                # install.install_logstash
                {
                    "configuration_directory": "/etc/dynamite/logstash/",
                    "install_directory": "/opt/dynamite/logstash/",
                    "log_directory": "/var/log/dynamite/logstash/",
                    "host": str(listen_address),
                    "elasticsearch_host": str(elasticsearch_host),
                    "elasticsearch_port": int(elasticsearch_port),
                    "elasticsearch_password": str(elasticsearch_password),
                    "heap_size_gigs": int(heap_size_gigs),
                    "install_jdk": bool(install_jdk),
                    "create_dynamite_user": True,
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },

                # log_message
                {
                    "msg": '*** LogStash installed successfully. ***',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },
                # log_message
                {
                    "msg": 'Next, Start your cluster: '
                           '\'dynamite logstash start\'.',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                }
            ),
            return_formats=(
                None,
                None,
                None,
                None,
                None
            ))


class LogstashUninstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to uninstall logstash
    """

    def __init__(self, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="logstash_uninstall",
            strategy_description="Uninstall LogStash.",
            functions=(
                install.uninstall_logstash,
                log_message
            ),
            arguments=(
                # install.uninstall_logstash
                {
                    "prompt_user": bool(prompt_user),
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },

                # log_message
                {
                    "msg": '*** LogStash uninstalled successfully. ***',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },
            ),
            return_formats=(
                None,
                None
            )
        )


class LogstashProcessStartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to start logstash
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="logstash_start",
            strategy_description="Start LogStash process.",
            functions=(
                process.start,
            ),
            arguments=(
                # process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
            ),
            return_formats=(
                None,
            )

        )
        if status:
            self.add_function(process.status, {}, return_format="json")


class LogstashProcessStopStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to stop logstash
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="logstash_stop",
            strategy_description="Stop LogStash process.",
            functions=(
                process.stop,
            ),
            arguments=(
                # process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
            ),
            return_formats=(
                None,
            )

        )
        if status:
            self.add_function(process.status, {}, return_format="json")


class LogstashProcessRestartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to restart logstash
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="logstash_restart",
            strategy_description="Restart LogStash process.",
            functions=(
                process.stop,
                process.start,
            ),
            arguments=(
                # process.stop
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },

                # process.start
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
        if status:
            self.add_function(process.status, {}, return_format="json")


class LogstashProcessStatusStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to get the status of logstash
    """

    def __init__(self):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="logstash_status",
            strategy_description="Get the status of the LogStash process.",
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
    ls_install_strategy = LogstashInstallStrategy(
        listen_address="0.0.0.0",
        elasticsearch_host="localhost",
        elasticsearch_port=9200,
        elasticsearch_password="changeme",
        check_elasticsearch_connection=False,
        heap_size_gigs=4,
        install_jdk=False,
        stdout=True,
        verbose=True
    )
    ls_install_strategy.execute_strategy()


def run_uninstall_strategy():
    ls_uninstall_strategy = LogstashUninstallStrategy(
        prompt_user=False,
        stdout=True,
        verbose=True
    )
    ls_uninstall_strategy.execute_strategy()


def run_process_start_strategy():
    ls_start_strategy = LogstashProcessStartStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    ls_start_strategy.execute_strategy()


def run_process_stop_strategy():
    ls_stop_strategy = LogstashProcessStopStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    ls_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    ls_restart_strategy = LogstashProcessRestartStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    ls_restart_strategy.execute_strategy()


def run_process_status_strategy():
    ls_status_strategy = LogstashProcessStatusStrategy()
    ls_status_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    run_process_start_strategy()
    run_process_stop_strategy()
    run_process_restart_strategy()
    run_process_status_strategy()
    run_uninstall_strategy()
    pass
