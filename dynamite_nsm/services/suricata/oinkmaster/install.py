import logging
import os
import subprocess
from typing import Optional

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.base import install


class UpdateSuricataRulesError(Exception):
    """
    Thrown when Suricata rules fail to update
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while updating Suricata rule-sets: {}".format(message)
        super(UpdateSuricataRulesError, self).__init__(msg)


class InstallManager(install.BaseInstallManager):
    """
    An interface for installing OinkMaster Suricata update script
    """

    def __init__(self, install_directory: str, download_oinkmaster_archive: Optional[bool] = True,
                 stdout: Optional[bool] = True, verbose: Optional[bool] = False):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/oinkmaster/)
        :param download_oinkmaster_archive: If True, download the Oinkmaster archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """

        self.install_directory = install_directory
        self.stdout = stdout
        self.verbose = verbose
        install.BaseInstallManager.__init__(self, 'oinkmaster', stdout=self.stdout, verbose=self.verbose)

        if download_oinkmaster_archive:
            self.logger.info("Attempting to download Oinkmaster archive.")
            self.download_from_mirror(const.OINKMASTER_MIRRORS, const.OINKMASTER_ARCHIVE_NAME, stdout=stdout,
                                      verbose=verbose)

        self.logger.info("Attempting to extract Oinkmaster archive ({}).".format(const.OINKMASTER_ARCHIVE_NAME))
        self.extract_archive(os.path.join(const.INSTALL_CACHE, const.OINKMASTER_ARCHIVE_NAME))
        self.logger.info("Extraction completed.")

    def setup_oinkmaster(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info("Installing Oinkmaster.")

        utilities.makedirs(self.install_directory, exist_ok=True)
        self.logger.info("Copying oinkmaster files.")
        utilities.copytree(os.path.join(const.INSTALL_CACHE, const.OINKMASTER_DIRECTORY_NAME),
                           self.install_directory)

        if 'OINKMASTER_HOME' not in open(env_file).read():
            self.logger.info('Updating Oinkmaster default home path [{}]'.format(self.install_directory))
            subprocess.call('echo OINKMASTER_HOME="{}" >> {}'.format(self.install_directory, env_file),
                            shell=True)
        self.logger.info('PATCHING oinkmaster.conf with emerging-threats URL.')
        with open(os.path.join(self.install_directory, 'oinkmaster.conf'), 'a') as f:
            f.write('\nurl = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz')


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
        raise UpdateSuricataRulesError(
            "Could not resolve SURICATA_CONFIG environment_variable. Is Suricata installed?")
    oinkmaster_install_directory = environment_variables.get('OINKMASTER_HOME')
    exit_code = subprocess.call('./oinkmaster.pl -C oinkmaster.conf -o {}'.format(
        os.path.join(suricata_config_directory, 'rules')), cwd=oinkmaster_install_directory, shell=True)
    if exit_code != 0:
        logger.error("Oinkmaster returned a non-zero exit-code: {}.".format(exit_code))
        raise UpdateSuricataRulesError("Oinkmaster returned a non-zero exit-code: {}".format(exit_code))
