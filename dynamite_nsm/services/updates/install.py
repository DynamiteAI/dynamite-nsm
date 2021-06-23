import os
import shutil
import time
from typing import Optional

from dynamite_nsm import const
from dynamite_nsm import exceptions
from dynamite_nsm.services.base import install
from dynamite_nsm.utilities import download_file
from dynamite_nsm.utilities import extract_archive
from dynamite_nsm.utilities import makedirs


class InstallManager(install.BaseInstallManager):

    def __init__(self, stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        super().__init__('updates', verbose, stdout)
        self.stdout = stdout
        self.verbose = verbose

    @staticmethod
    def update_default_configurations():
        """
        Retrieves the latest skeleton configurations for setting up ElasticSearch, LogStash, Kibana, Zeek, Suricata,
        and Filebeat
        """
        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        makedirs(const.DEFAULT_CONFIGS, exist_ok=True)
        try:
            download_file(const.DEFAULT_CONFIGS_URL,
                          const.DEFAULT_CONFIGS_ARCHIVE_NAME, stdout=True)
        except Exception as e:
            raise exceptions.DownloadError("General error occurred while downloading archive: {}; {}".format(
                os.path.join(const.INSTALL_CACHE, 'default_configs.tar.gz'), e))
        shutil.rmtree(const.DEFAULT_CONFIGS, ignore_errors=True)
        time.sleep(1)
        try:
            extract_archive(os.path.join(const.INSTALL_CACHE, 'default_configs.tar.gz'), const.CONFIG_PATH)
        except IOError as e:
            raise exceptions.ArchiveExtractionError("General error occurred while extracting archive: {}; {}".format(
                os.path.join(const.INSTALL_CACHE, 'default_configs.tar.gz'), e))

    @staticmethod
    def update_mirrors():
        """
        Retrieves the latest mirrors which contain the download locations for all components
        """

        shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
        makedirs(const.MIRRORS, exist_ok=True)
        try:
            download_file(const.MIRRORS_CONFIG_URL,
                          const.MIRRORS_CONFIG_ARCHIVE_NAME, stdout=True)
        except Exception as e:
            raise exceptions.DownloadError("General error occurred while downloading archive: {}; {}".format(
                os.path.join(const.INSTALL_CACHE, 'mirrors.tar.gz'), e))
        shutil.rmtree(const.MIRRORS, ignore_errors=True)
        try:
            extract_archive(os.path.join(const.INSTALL_CACHE, 'mirrors.tar.gz'), const.CONFIG_PATH)
            return True
        except IOError as e:
            raise exceptions.DownloadError("General error occurred while extracting archive: {}; {}".format(
                os.path.join(const.INSTALL_CACHE, 'mirrors.tar.gz'), e))

    def setup(self):
        """
        Download updates and setup them up.
        """
        self.logger.info(
            'Attempting to download the latest mirrors and default configurations for installable components.')
        self.update_mirrors()
        self.update_default_configurations()
        self.logger.info(
            'Updates have been applied. The next time you install: elasticsearch, logstash, kibana, zeek, suricata, '
            'or filebeat these updates will be applied to that component.')


if __name__ == '__main__':
    install_mngr = InstallManager(
        stdout=True,
        verbose=True
    )
    install_mngr.setup()
