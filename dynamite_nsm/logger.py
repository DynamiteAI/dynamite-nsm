import os
import logging
import coloredlogs
from datetime import datetime

from dynamite_nsm import const
from dynamite_nsm import utilities

TODAY_FORMATTED_DATE = datetime.strftime(datetime.today(), '%d-%m-%Y')


def get_logger(component_name, level=logging.INFO, stdout=True) -> logging.Logger:
    """Get a pre-configured logging instance

    Args:
        component_name: The name of the service doing the logging.
        level: The minimum logging level
        stdout: If True, prints to console

    Returns: A logger instance
    """
    coloredlogs.DEFAULT_FIELD_STYLES = {'asctime': {'color': 'green'}, 'hostname': {'color': 'magenta'},
                                        'levelname': {'bold': True, 'color': 'black'},
                                        'name': {'color': 'cyan', 'bold': True},
                                        'programname': {'color': 'blue'}, 'username': {'color': 'yellow'}}

    utilities.makedirs(const.LOG_PATH, exist_ok=True)

    logger = logging.getLogger(component_name.upper())
    logger.setLevel(level)
    if not len(logger.handlers):
        fh = logging.FileHandler(os.path.join(const.LOG_PATH, 'dynamite-{}.log'.format(TODAY_FORMATTED_DATE)))
        fformatter = logging.Formatter(
            '%(asctime)s | %(name)20s | %(module)20s | %(funcName)45s | %(lineno)4s | %(levelname)8s |  %(message)s')
        fh.setFormatter(fformatter)
        logger.addHandler(fh)
    if stdout:
        coloredlogs.install(level=level, logger=logger,
                            fmt='%(asctime)s %(name)-25s %(levelname)-10s | %(message)s')
    logger.propagate = False
    return logger
