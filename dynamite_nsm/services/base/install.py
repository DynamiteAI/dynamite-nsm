import logging
import tarfile

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions


class BaseInstallManager:

    def __init__(self, name, verbose=False, stdout=True):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger(str(name).upper(), level=log_level, stdout=stdout)

    @staticmethod
    def download_from_mirror(mirror_path, fname, stdout=False, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('BASESVC', level=log_level, stdout=stdout)

        with open(mirror_path) as mirror_f:
            res, err = None, None
            for url in mirror_f.readlines():
                logger.info("Downloading {} from {}".format(fname,  url))
                try:
                    res = utilities.download_file(url, fname, stdout=stdout)
                except Exception as e:
                    res, err = False, e
                    logger.warning("Failed to download {} from {}; {}".format(fname, url, e))
                if res:
                    break
            if not res:
                raise general_exceptions.DownloadError(
                    "General error while attempting to download {} from all mirrors ;".format(fname))

    @staticmethod
    def extract_archive(archive_path):
        try:
            tf = tarfile.open(archive_path)
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract {} archive to {}; {}".format(archive_path, const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract {}} archive; {}".format(archive_path, e))
