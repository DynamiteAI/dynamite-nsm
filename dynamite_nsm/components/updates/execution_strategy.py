import logging
from dynamite_nsm import updater
from dynamite_nsm.logger import get_logger
from dynamite_nsm.components.base import execution_strategy


def log_message(msg, level=logging.INFO, stdout=True, verbose=False):
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('UPDATES_CMP', level=log_level, stdout=stdout)
    if level == logging.DEBUG:
        logger.debug(msg)
    elif level == logging.INFO:
        logger.info(msg)
    elif level == logging.WARNING:
        logger.warning(msg)
    elif level == logging.ERROR:
        logger.error(msg)


class UpdateInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install the latest copy of mirrors and default configs
    """

    def __init__(self, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="agent_dependency_install",
            strategy_description="Install Linux kernel development headers.",
            functions=(
                updater.update_default_configurations,
                updater.update_mirrors,
                log_message
            ),
            arguments=(
                # updater.update_default_configurations,
                {},
                # updater.update_mirrors
                {},
                # log_message
                {'msg': 'Mirrors and default configurations have been updated. '
                        'The next time you install a component, these new configurations will be used.',
                 'stdout': bool(stdout),
                 'verbose': bool(verbose)
                 }),
            return_formats=(
                None,
                None,
                None
            )
        )


# Test Functions


def run_install_strategy():
    updt_deps_install_strategy = UpdateInstallStrategy(
        stdout=True,
        verbose=True
    )
    updt_deps_install_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    pass
