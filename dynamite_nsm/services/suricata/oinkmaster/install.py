import os
from typing import Optional

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import install


class InstallManager(install.BaseInstallManager):
    """
    An interface for installing OinkMaster Suricata update script
    """

    def __init__(self, install_directory: str, download_oinkmaster_archive: Optional[bool] = True,
                 stdout: Optional[bool] = True, verbose: Optional[bool] = False):
        """Initialize Rule Installer
        Args:
            install_directory: Path to the install directory (E.G /opt/dynamite/oinkmaster/)
            download_oinkmaster_archive: If True, download the Oinkmaster archive from a mirror
            stdout: Print the output to console
            verbose: Include output from system utilities
        Returns:
            None
        """

        self.install_directory = install_directory
        self.stdout = stdout
        self.verbose = verbose
        install.BaseInstallManager.__init__(self, 'oinkmaster.install', stdout=self.stdout, verbose=self.verbose,
                                            requires_root=False)

        if download_oinkmaster_archive:
            self.logger.info("Attempting to download Oinkmaster archive.")
            _, archive_name, self.local_mirror_root = self.download_from_mirror(const.OINKMASTER_MIRRORS)
            self.logger.info(f'Attempting to extract Oinkmaster archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.local_mirror_root = self.get_mirror_info(const.OINKMASTER_MIRRORS)

    def create_update_oinkmaster_environment_variables(self) -> None:
        """Creates the required Oinkmaster environmental variable
        Returns:
            None
        """
        self.create_update_env_variable('OINKMASTER_HOME', self.install_directory)

    def setup(self):
        utilities.makedirs(self.install_directory)
        self.create_update_oinkmaster_environment_variables()
        utilities.copytree(
            f'{const.INSTALL_CACHE}/{self.local_mirror_root}',
            self.install_directory
        )
        with open(os.path.join(self.install_directory, 'oinkmaster.conf'), 'a') as f:
            f.write(f'\nurl = {const.EMERGING_THREATS_OPEN}')


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/suricata/oinkmaster',
        download_oinkmaster_archive=True,
        stdout=True,
        verbose=True
    )
    install_mngr.setup()
