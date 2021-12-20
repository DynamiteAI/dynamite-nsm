import sys
from typing import Optional

from dynamite_nsm.services.base import install
from dynamite_nsm.services.base import tasks


class InstallManager(install.BaseInstallManager):
    """
    An interface for installing OinkMaster Suricata update script
    """

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False):
        """Initialize ZKG Installer
        Args:
            stdout: Print the output to console
            verbose: Include output from system utilities
        Returns:
            None
        """

        self.stdout = stdout
        self.verbose = verbose
        install.BaseInstallManager.__init__(self, 'zkg.install', stdout=self.stdout, verbose=self.verbose)

    def install_zkg_dependencies(self):
        self.install_dependencies(apt_get_packages=['git'], yum_packages=['git'])
        git_python_package = tasks.BasePythonPackageInstallTask(
            name='GitPython', package_link='GitPython==3.1.18',
            description='A Python library used to interact with git repositories',
            command='', args=[])
        git_python_package.download_and_install()

        semantic_version_package = tasks.BasePythonPackageInstallTask(
            name='semantic-version', package_link='semantic-version==2.8.5',
            description='python library provides a few tools to handle SemVer in Python',
            command='', args=[])
        semantic_version_package.download_and_install()

    def setup(self):
        self.create_update_env_variable('ZKG_PYTHON_BIN', sys.executable)
        self.install_zkg_dependencies()


if __name__ == '__main__':
    install_mngr = InstallManager(
        stdout=True,
        verbose=True
    )
    install_mngr.setup()

