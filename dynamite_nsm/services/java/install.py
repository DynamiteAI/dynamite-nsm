import os
from typing import Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.services.base import install


class InstallManager(install.BaseInstallManager):

    def __init__(self, install_directory: str, download_java_archive: Optional[bool] = True,
                 stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        super().__init__('java.install', verbose, stdout)
        self.install_directory = install_directory
        self.stdout = stdout
        self.verbose = verbose

        if download_java_archive:
            self.logger.info("Attempting to download OpenJDK archive.")
            _, archive_name, self.directory_name = self.download_from_mirror(const.JAVA_MIRRORS)
            self.logger.info(f'Attempting to extract OpenJDK archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.directory_name = self.get_mirror_info(const.JAVA_MIRRORS)

    def copy_java_files_and_directories(self) -> None:
        """
        Copy the required Java files from the install cache to their respective directories
        """
        java_tarball_extracted = f'{const.INSTALL_CACHE}/{self.directory_name}'
        install_paths = [
            'bin/',
            'conf/',
            'include/',
            'jmods/',
            'legal/',
            'lib/',
            'release'
        ]
        for inst in install_paths:
            self.copy_file_or_directory_to_destination(f'{java_tarball_extracted}/{inst}',
                                                       f'{self.install_directory}/{self.directory_name}')

    def create_update_java_environment_variables(self) -> None:
        """
        Creates all the required Java environmental variables
        """
        self.create_update_env_variable('JAVA_HOME', f'{self.install_directory}/{self.directory_name}')

    def setup(self):
        utilities.makedirs(self.install_directory)
        utilities.makedirs(f'{self.install_directory}/{self.directory_name}')
        self.copy_java_files_and_directories()
        self.create_update_java_environment_variables()
        utilities.set_ownership_of_file(f'{self.install_directory}/{self.directory_name}', user='dynamite',
                                        group='dynamite')


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=const.JVM_ROOT,
        download_java_archive=True,
        stdout=True,
        verbose=True
    )
    install_mngr.setup()
