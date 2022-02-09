import os
import logging
import coloredlogs
from datetime import datetime

from dynamite_remote import utilities
user_home = os.environ.get('HOME')

LOG_PATH = f'{user_home}/.dynamite_remote/logs'


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

    utilities.makedirs(LOG_PATH, exist_ok=True)
    today_formatted_date = datetime.strftime(datetime.today(), '%d-%m-%Y')
    logger = logging.getLogger(component_name)
    logger.setLevel(level)
    if not len(logger.handlers):
        fh = logging.FileHandler(os.path.join(LOG_PATH, 'dynamite-remote-{}.log'.format(today_formatted_date)))
        fformatter = logging.Formatter(
            '%(asctime)s | %(name)5s | %(module)5s | %(funcName)5s | %(lineno)4s | %(levelname)8s |  %(message)s')
        fh.setFormatter(fformatter)
        logger.addHandler(fh)
    if stdout:
        coloredlogs.install(level=level, logger=logger,
                            fmt='%(asctime)s %(name)-15s %(levelname)-10s | %(message)s')
    logger.propagate = False
    return logger
