import os
import logging
import coloredlogs
from datetime import datetime

from dynamite_nsm import const
from dynamite_nsm import utilities


def get_logger(component_name, level=logging.INFO, stdout=True):
    coloredlogs.DEFAULT_FIELD_STYLES = {'asctime': {'color': 'green'}, 'hostname': {'color': 'magenta'},
                                        'levelname': {'bold': True, 'color': 'black'},
                                        'name': {'color': 'cyan', 'bold': True},
                                        'programname': {'color': 'blue'}, 'username': {'color': 'yellow'}}

    utilities.makedirs(const.LOG_PATH, exist_ok=True)
    today_formatted_date = datetime.strftime(datetime.today(), '%d-%m-%Y')
    logger = logging.getLogger(component_name)
    logger.setLevel(level)
    fh = logging.FileHandler(os.path.join(const.LOG_PATH, 'dynamite-{}.log'.format(today_formatted_date)))
    fformatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    fh.setFormatter(fformatter)
    logger.addHandler(fh)
    if stdout:
        coloredlogs.install(level=level, logger=logger,
                            fmt='%(asctime)s %(name)-15s %(levelname)-10s | %(message)s')
    return logger