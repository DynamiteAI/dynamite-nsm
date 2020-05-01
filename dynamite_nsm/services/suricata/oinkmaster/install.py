import os
import sys
import logging
import tarfile
import subprocess

from dynamite_nsm.logger import get_logger

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.suricata.oinkmaster import exceptions as oinkmaster_exceptions


class InstallManager:
    """
    An interface for installing OinkMaster Suricata update script
    """

    def __init__(self, install_directory, download_oinkmaster_archive=True, stdout=True, verbose=False):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/oinkmaster/)
        :param download_oinkmaster_archive: If True, download the Oinkmaster archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('OINKMASTER', level=log_level, stdout=stdout)

        self.install_directory = install_directory
        self.stdout = stdout
        self.verbose = verbose
        if download_oinkmaster_archive:
            try:
                self.logger.info("Attempting to download Oinkmaster archive.")
                self.download_oinkmaster(stdout=stdout)
            except general_exceptions.DownloadError as e:
                self.logger.error("Failed to download Oinkmaster archive.")
                self.logger.debug("Failed to download Oinkmaster archive, threw: {}.".format(e))
                raise oinkmaster_exceptions.InstallOinkmasterError("Failed to download Oinkmaster archive.")
        try:
            self.logger.info("Attempting to extract Oinkmaster archive ({}).".format(const.OINKMASTER_ARCHIVE_NAME))
            self.extract_oinkmaster()
            self.logger.info("Extraction completed.")
        except general_exceptions.ArchiveExtractionError as e:
            self.logger.error("Failed to extract Oinkmaster archive.")
            self.logger.debug("Failed to extract Oinkmaster archive, threw: {}.".format(e))
            raise oinkmaster_exceptions.InstallOinkmasterError("Failed to extract Oinkmaster archive.")

    @staticmethod
    def download_oinkmaster(stdout=False):
        """
        Download Oinkmaster archive

        :param stdout: Print output to console
        """

        url = None
        try:
            with open(const.OINKMASTER_MIRRORS, 'r') as oinkmaster_archive:
                for url in oinkmaster_archive.readlines():
                    if utilities.download_file(url, const.OINKMASTER_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading Oinkmaster from {}; {}".format(url, e))

    @staticmethod
    def extract_oinkmaster():
        """
        Extract Oinkmaster to local install_cache
        """

        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.OINKMASTER_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract Oinkmaster archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract Oinkmaster archive; {}".format(e))

    def setup_oinkmaster(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info("Installing Oinkmaster.")
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
        except Exception as e:
            self.logger.error("Failed to create required directory structure.")
            self.logger.debug("Failed to create required directory structure; {}".format(e))
            raise oinkmaster_exceptions.InstallOinkmasterError(
                "Failed to create required directory structure; {}".format(e))
        self.logger.info("Copying oinkmaster files.")
        try:
            utilities.copytree(os.path.join(const.INSTALL_CACHE, const.OINKMASTER_DIRECTORY_NAME),
                               self.install_directory)
        except Exception as e:
            self.logger.error(
                'Failed to copy {} -> {}.'.format(os.path.join(const.INSTALL_CACHE, const.OINKMASTER_DIRECTORY_NAME),
                                                  self.install_directory))
            self.logger.debug(sys.stderr.write('Failed to copy {} -> {}: {}'.format(
                os.path.join(const.INSTALL_CACHE, const.OINKMASTER_DIRECTORY_NAME), self.install_directory, e)))
            raise oinkmaster_exceptions.InstallOinkmasterError(
                "General error while copying Oinkmaster from install cache; {}".format(e))
        if 'OINKMASTER_HOME' not in open(env_file).read():
            self.logger.info('Updating Oinkmaster default home path [{}]'.format(self.install_directory))
            subprocess.call('echo OINKMASTER_HOME="{}" >> {}'.format(self.install_directory, env_file),
                            shell=True)
        self.logger.info('PATCHING oinkmaster.conf with emerging-threats URL.')
        try:
            with open(os.path.join(self.install_directory, 'oinkmaster.conf'), 'a') as f:
                f.write('\nurl = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz')
        except Exception as e:
            self.logger.error('Failed to update oinkmaster.conf.')
            self.logger.debug('Failed to update oinkmaster.conf: {}.\n'.format(e))
            raise oinkmaster_exceptions.InstallOinkmasterError(
                "Failed to update oinkmaster configuration file; {}".format(e))


def update_suricata_rules(stdout=True, verbose=False):
    """
    Update Suricata rules specified in the oinkmaster.conf file

    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('OINKMASTER', level=log_level, stdout=stdout)
    environment_variables = utilities.get_environment_file_dict()
    suricata_config_directory = environment_variables.get('SURICATA_CONFIG')
    if not suricata_config_directory:
        logger.error("Could not resolve SURICATA_CONFIG environment_variable. Is Suricata installed?")
        raise oinkmaster_exceptions.UpdateSuricataRulesError(
            "Could not resolve SURICATA_CONFIG environment_variable. Is Suricata installed?")
    oinkmaster_install_directory = environment_variables.get('OINKMASTER_HOME')
    exit_code = subprocess.call('./oinkmaster.pl -C oinkmaster.conf -o {}'.format(
        os.path.join(suricata_config_directory, 'rules')), cwd=oinkmaster_install_directory, shell=True)
    if exit_code != 0:
        logger.error("Oinkmaster returned a non-zero exit-code: {}.".format(exit_code))
        raise oinkmaster_exceptions.UpdateSuricataRulesError(
            "Oinkmaster returned a non-zero exit-code: {}".format(exit_code))
