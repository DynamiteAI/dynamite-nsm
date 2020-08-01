import os


class BaseProcessProfiler:

    def __init__(self, install_directory, config_directory, install_archive_path, required_install_files=(),
                 required_config_files=()):
        self.install_directory = install_directory
        self.config_directory = config_directory
        self.install_archive_path = install_archive_path
        self.required_install_files = required_install_files
        self.required_config_files = required_config_files

    def is_configured(self):
        if not self.config_directory:
            return False
        if not os.path.exists(self.config_directory):
            return False
        for config_file in self.required_config_files:
            if config_file not in os.listdir(self.config_directory):
                return False
        return True

    def is_downloaded(self):
        return os.path.exists(self.install_archive_path)

    def is_installed(self):
        if not self.install_directory:
            return False
        if not os.path.exists(self.install_directory):
            return False
        for install_file in self.required_install_files:
            if install_file not in os.listdir(self.install_directory):
                return False
        return True



