from typing import List, Optional
from dynamite_nsm import const
from dynamite_nsm.services.zeek.zkg import install_zeek_package
from dynamite_nsm.services.base.install import BaseInstallManager


class InstallPackageManager(BaseInstallManager):

    def __init__(self, package_git_urls: List[str], stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """Install Zeek package
        Args:
            package_git_urls: One or more paths to git repo containing the Zeek packages to install
            stdout: Print the output to console
            verbose: Include detailed debug messages
        Returns:
            None
        """
        self.package_git_urls = package_git_urls
        super().__init__('zeek.package.install', stdout=stdout, verbose=verbose)

    def setup(self):
        """Start the update process
        Returns:
            None
        """
        for package_url in self.package_git_urls:
            self.logger.info(f'Installing {package_url}.')
            install_zeek_package(package_url, stdout=self.stdout, verbose=self.verbose)


if __name__ == '__main__':
    InstallPackageManager(const.ZEEK_PACKAGES).setup()
