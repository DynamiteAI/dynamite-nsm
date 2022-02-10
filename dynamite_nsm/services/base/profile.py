import os
from dynamite_nsm import exceptions, utilities


class BaseProcessProfiler:
    """
    Process Profiler base class
    """
    def __init__(self, install_directory, config_directory, required_install_files=(),
                 required_config_files=()):
        """Build a process profiler for a service
        Args:
            install_directory: The directory where the service is installed
            config_directory: The directory holding configuration related files
            required_install_files: The names of files required to consider the installation successful
            required_config_files: The names of config files to consider the installation properly configured.
        """
        if not utilities.is_setup():
            raise exceptions.DynamiteNotSetupError()
        self.install_directory = install_directory
        self.config_directory = config_directory
        self.required_install_files = required_install_files
        self.required_config_files = required_config_files

    def is_configured(self) -> bool:
        """Determine if the instance is properly configured

        Returns:
            True if properly configured
        """
        if not self.config_directory:
            return False
        if not os.path.exists(self.config_directory):
            return False
        for config_file in self.required_config_files:
            if config_file not in os.listdir(self.config_directory):
                return False
        return True

    def is_installed(self) -> bool:
        """Determine if the instance is properly installed

        Returns:
            True if properly installed
        """
        if not self.install_directory:
            return False
        if not os.path.exists(self.install_directory):
            return False
        for install_file in self.required_install_files:
            if install_file not in os.listdir(self.install_directory):
                return False
        return True




