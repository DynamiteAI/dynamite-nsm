import os
import logging
from dynamite_nsm import const
from datetime import datetime


class ConsoleFormatter(logging.Formatter):
    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
    err_fmt = "[x] %(msg)s"
    wrn_fmt = "[w] %(msg)s"
    inf_fmt = "[+] %(msg)s"
    dbg_fmt = "[?] %(module)s: %(lineno)d: %(msg)s"

    def __init__(self, fmt="%(levelno)s: %(msg)s"):
        logging.Formatter.__init__(self, fmt)

    def format(self, record):

        # Save the original format configured by the user
        # when the logger formatter was instantiated
        try:
            format_orig = self._style._fmt
        except AttributeError:
            format_orig = self._fmt
        # Replace the original format with one customized by logging level
        if record.levelno == logging.DEBUG:
            try:
                self._style._fmt = ConsoleFormatter.dbg_fmt
            except AttributeError:
                self._fmt = ConsoleFormatter.dbg_fmt

        elif record.levelno == logging.INFO:
            try:
                self._style._fmt = ConsoleFormatter.inf_fmt
            except AttributeError:
                self._fmt = ConsoleFormatter.inf_fmt
        elif record.levelno == logging.WARNING:
            try:
                self._style._fmt = ConsoleFormatter.wrn_fmt
            except AttributeError:
                self._fmt = ConsoleFormatter.wrn_fmt
        elif record.levelno == logging.ERROR:
            try:
                self._style._fmt = ConsoleFormatter.err_fmt
            except AttributeError:
                self._fmt = ConsoleFormatter.err_fmt

        # Call the original formatter class to do the grunt work
        result = logging.Formatter.format(self, record)

        # Restore the original format configured by the user
        try:
            self._style._fmt = format_orig

        except AttributeError:
            self._fmt = format_orig
        return result


def get_logger(component_name, level=logging.INFO, stdout=True):
    today_formatted_date = datetime.strftime(datetime.today(), '%d-%m-%Y')
    logger = logging.getLogger(component_name)
    logger.setLevel(level)
    fh = logging.FileHandler(os.path.join(const.LOG_PATH, 'dynamite-{}.log'.format(today_formatted_date)))
    ch = logging.StreamHandler()
    fformatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    cformatter = ConsoleFormatter()

    fh.setFormatter(fformatter)
    ch.setFormatter(cformatter)
    logger.addHandler(fh)
    if stdout:
        logger.addHandler(ch)
    return logger
