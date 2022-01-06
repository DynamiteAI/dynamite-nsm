from typing import List, Optional

from dynamite_nsm.services.base import install
from dynamite_nsm.services.zeek import install as zeek_install
from dynamite_nsm.services.filebeat import install as filebeat_install
from dynamite_nsm.services.suricata import install as suricata_install
from dynamite_nsm.services.agent import optimize


class InstallManager(install.BaseInstallManager):

    def __init__(self, filebeat_install_directory: str,
                 suricata_configuration_directory: Optional[str] = None,
                 suricata_install_directory: Optional[str] = None,
                 suricata_log_directory: Optional[str] = None,
                 zeek_configuration_directory: Optional[str] = None, zeek_install_directory: Optional[str] = None,
                 stdout: Optional[bool] = False, verbose: Optional[bool] = False
                 ):
        """Manage agent installation process

        Args:
            filebeat_install_directory: The path to the Filebeat install directory (Default - /opt/dynamite/filebeat)
            suricata_configuration_directory: The path to the Suricata config directory (Default - /etc/dynamite/suricata)
            suricata_install_directory: The path to the Suricata install directory (Default - /opt/dynamite/suricata)
            suricata_log_directory: The path to the Suricata log directory (Default - /var/log/suricata)
            zeek_configuration_directory: The path to the Zeek configuration directory (Default - /etc/dynamite/zeek)
            zeek_install_directory: The path to the Zeek installation directory (Default - /opt/dynamite/zeek)
            stdout: Print the output to console
            verbose: Include detailed debug messages
        """
        super().__init__('agent.install', stdout=stdout, verbose=verbose)
        self.filebeat_install_directory = filebeat_install_directory
        self.suricata_configuration_directory = suricata_configuration_directory
        self.suricata_log_directory = suricata_log_directory
        self.suricata_install_directory = suricata_install_directory
        self.zeek_configuration_directory = zeek_configuration_directory
        self.zeek_install_directory = zeek_install_directory

    def setup(self, inspect_interfaces: List[str], targets: List[str],
              target_type: Optional[str] = 'elasticsearch') -> None:
        """ Setup Zeek, Suricata and Filebeat on the same physical instance.
        Args:
            inspect_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
            targets: One or more URLs to send event/alerts to (E.G https://my_elasticsearch_collector.local:9200)
            target_type: The target type; current supported: elasticsearch (default), logstash, kafka, redis

        Returns:
            None
        """
        if self.suricata_install_directory or self.suricata_configuration_directory or self.suricata_log_directory:
            if not (
                    self.suricata_install_directory and self.suricata_configuration_directory
                    and self.suricata_log_directory
            ):
                self.logger.error(
                    'You must specify suricata-configuration-directory, suricata-install-directory, '
                    'and suricata-log-directory.')
                return None

            suricata_install.InstallManager(configuration_directory=self.suricata_configuration_directory,
                                            install_directory=self.suricata_install_directory,
                                            log_directory=self.suricata_log_directory, download_suricata_archive=True,
                                            stdout=self.stdout, verbose=self.verbose).setup(inspect_interfaces)
        if self.zeek_install_directory or self.zeek_install_directory:
            if not (self.zeek_install_directory and self.zeek_configuration_directory):
                self.logger.error(
                    'You must specify both the zeek-configuration-directory and zeek-install-directory.')
                return None
            zeek_install.InstallManager(configuration_directory=self.zeek_configuration_directory,
                                        install_directory=self.zeek_install_directory, download_zeek_archive=True,
                                        stdout=self.stdout, verbose=self.verbose).setup(inspect_interfaces)
        filebeat_install.InstallManager(install_directory=self.filebeat_install_directory,
                                        download_filebeat_archive=True, stdout=self.stdout,
                                        verbose=self.verbose).setup(targets=targets, target_type=target_type)
        optimize.OptimizeThreadingManager(self.suricata_configuration_directory, self.zeek_install_directory,
                                          stdout=self.stdout, verbose=self.verbose).optimize()


class UninstallManager(install.BaseUninstallManager):

    def __init__(self, stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """Manage agent uninstall process

        Args:
            stdout: Print the output to console
            verbose: Include detailed debug messages
        """
        super().__init__(directories=[], name='agent.uninstall', stdout=stdout, verbose=verbose)

    def uninstall(self) -> None:
        """Uninstall Zeek, Suricata and Filebeat from this instance.
        Returns:
            None
        """
        from dynamite_nsm.services.zeek import profile as zeek_profile
        from dynamite_nsm.services.suricata import profile as suricata_profile

        filebeat_install.UninstallManager(self.stdout, self.verbose).uninstall()
        if zeek_profile.ProcessProfiler().is_installed():
            zeek_install.UninstallManager(purge_config=True, stdout=self.stdout, verbose=self.verbose).uninstall()
        if suricata_profile.ProcessProfiler().is_installed():
            suricata_install.UninstallManager(purge_config=True, stdout=self.stdout, verbose=self.verbose).uninstall()
