import logging


from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.dynamited import install
from dynamite_nsm.services.dynamited import process
from dynamite_nsm.components.base import execution_strategy


def log_message(msg, level=logging.INFO, stdout=True, verbose=False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('DYNAMITED_CMP', level=log_level, stdout=stdout)
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


class DynamitedInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install dynamited
    """

    def __init__(self, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="dynamited_install",
            strategy_description="Install Dynamite Daemon",
            functions=(
                install.install_dynamited,
                log_message,
            ),
            arguments=(
                # install.install_dynamited
                {
                    "configuration_directory": "/etc/dynamite/dynamited/",
                    "install_directory": "/opt/dynamite/dynamited/",
                    "log_directory": "/var/log/dynamite/dynamited/",
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },

                # log_message
                {
                    "msg": 'Dynamited service installed successfully',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                }
            ),
            return_formats=(
                None,
                None,
            ))


class DynamitedUninstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to uninstall dynamited
    """

    def __init__(self, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="dynamited_uninstall",
            strategy_description="Uninstall Dynamite Daemon.",
            functions=(
                install.uninstall_dynamited,
                log_message
            ),
            arguments=(
                # install.uninstall_dynamited
                {
                    "prompt_user": bool(prompt_user),
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },

                # log_message
                {
                    "msg": '*** Dynamite Daemon uninstalled successfully. ***',
                    'stdout': bool(stdout),
                    'verbose': bool(verbose)
                },
            ),
            return_formats=(
                None,
                None
            )
        )


class DynamitedProcessStartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to start dynamited
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="dynamited_start",
            strategy_description="Start dynamited process.",
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


class DynamitedProcessStopStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to stop dynamited
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="dynamited_stop",
            strategy_description="Stop dynamited process.",
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


class DynamitedProcessRestartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to restart dynamited
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="dynamited_restart",
            strategy_description="Restart dynamited process.",
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


class DynamitedProcessStatusStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to get the status of dynamited
    """

    def __init__(self, stdout=True, verbose=False):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="dynamited_status",
            strategy_description="Get the status of the dynamited process.",
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
    dynamited_install_strategy = DynamitedInstallStrategy(
        stdout=True,
        verbose=True
    )
    dynamited_install_strategy.execute_strategy()


def run_process_start_strategy():
    dynamited_start_strategy = DynamitedProcessStartStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    dynamited_start_strategy.execute_strategy()


def run_process_stop_strategy():
    dynamited_stop_strategy = DynamitedProcessStopStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    dynamited_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    dynamited_restart_strategy = DynamitedProcessRestartStrategy(
        status=True,
        stdout=True,
        verbose=True
    )
    dynamited_restart_strategy.execute_strategy()


def run_process_status_strategy():
    dynamited_status_strategy = DynamitedProcessStatusStrategy()
    dynamited_status_strategy.execute_strategy()


if __name__ == '__main__':
    # run_install_strategy()
    run_process_start_strategy()
    #run_process_stop_strategy()
    #run_process_restart_strategy()
    #run_process_status_strategy()
    pass
