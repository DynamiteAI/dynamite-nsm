import logging


from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.managerd import install
from dynamite_nsm.services.managerd import process
from dynamite_nsm.components.base import execution_strategy


def log_message(msg, level=logging.INFO, stdout=True, verbose=False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('MANAGERD_CMP', level=log_level, stdout=stdout)
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


class ManagerdInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install managerd
    """

    def __init__(self, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="managerd_install",
            strategy_description="Install Manager Daemon",
            functions=(
                install.install_managerd,
                log_message,
            ),
            arguments=(
                # install.install_managerd
                {
                    "configuration_directory": "/etc/dynamite/managerd/",
                    "install_directory": "/opt/dynamite/managerd/",
                    "log_directory": "/var/log/dynamite/managerd/",
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },

                # log_message
                {
                    "msg": 'Managerd service installed successfully',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                }
            ),
            return_formats=(
                None,
                None,
            ))


class ManagerdUninstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to uninstall managerd
    """

    def __init__(self, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="managerd_uninstall",
            strategy_description="Uninstall Manager Daemon.",
            functions=(
                install.uninstall_managerd,
                log_message
            ),
            arguments=(
                # install.uninstall_managerd
                {
                    "prompt_user": bool(prompt_user),
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },

                # log_message
                {
                    "msg": '*** Manager Daemon uninstalled successfully. ***',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },
            ),
            return_formats=(
                None,
                None
            )
        )


class ManagerdProcessStartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to start managerd
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="managerd_start",
            strategy_description="Start Managerd process.",
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
            self.add_function(process.status, {'pretty_print_status': True}, return_format="text")


class ManagerdProcessStopStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to stop managerd
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="managerd_stop",
            strategy_description="Stop managerd process.",
            functions=(
                process.stop,
            ),
            arguments=(
                # process.stop
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
            self.add_function(process.status, {'pretty_print_status': True}, return_format="text")


class ManagerdProcessRestartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to restart managerd
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="managerd_restart",
            strategy_description="Restart managerd process.",
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
                    "verbose": bool(verbose),
                },
            ),
            return_formats=(
                None,
                None
            )
        )
        if status:
            self.add_function(process.status, {'pretty_print_status': True}, return_format="text")


class ManagerdProcessStatusStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to get the status of managerd
    """

    def __init__(self, stdout=True, verbose=False):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="managerd_status",
            strategy_description="Get the status of the managerd process.",
            functions=(
                process.status,
            ),
            arguments=(
                # process.status
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                    "pretty_print_status": True
                },
            ),
            return_formats=(
                'text',
            )
        )


# Test Functions

def run_install_strategy():
    managerd_install_strategy = ManagerdInstallStrategy(
        stdout=True,
        verbose=True
    )
    managerd_install_strategy.execute_strategy()


def run_process_start_strategy():
    managerd_start_strategy = ManagerdProcessStartStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    managerd_start_strategy.execute_strategy()


def run_process_stop_strategy():
    managerd_stop_strategy = ManagerdProcessStopStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    managerd_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    managerd_restart_strategy = ManagerdProcessRestartStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    managerd_restart_strategy.execute_strategy()


def run_process_status_strategy():
    managerd_status_strategy = ManagerdProcessStatusStrategy()
    managerd_status_strategy.execute_strategy()


if __name__ == '__main__':
    # run_install_strategy()
    run_process_start_strategy()
    #run_process_stop_strategy()
    #run_process_restart_strategy()
    #run_process_status_strategy()
    pass
