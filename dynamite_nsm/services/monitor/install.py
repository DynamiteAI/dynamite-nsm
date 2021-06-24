from typing import List, Optional

from dynamite_nsm import utilities
from dynamite_nsm.services.base import install
from dynamite_nsm.services.kibana import install as kibana_install
from dynamite_nsm.services.logstash import install as logstash_install
from dynamite_nsm.services.elasticsearch import install as elasticsearch_install


class InstallManager(install.BaseInstallManager):

    def __init__(self, elasticsearch_install_directory: str,
                 elasticsearch_configuration_directory: Optional[str] = None,
                 elasticsearch_log_directory: Optional[str] = None,
                 logstash_install_directory: Optional[str] = None,
                 logstash_configuration_directory: Optional[str] = None,
                 logstash_log_directory: Optional[str] = None,
                 kibana_install_directory: Optional[str] = None,
                 kibana_configuration_directory: Optional[str] = None,
                 kibana_log_directory: Optional[str] = None,
                 stdout: Optional[bool] = False, verbose: Optional[bool] = False
                 ):
        """Install Elaticsearch, Logstash, and Kibana
        Args:
            elasticsearch_install_directory: Path to the elasticsearch install directory (E.G /opt/dynamite/elasticsearch/)
            elasticsearch_configuration_directory: Path to the elasticsearch configuration directory (E.G /etc/dynamite/elasticsearch/)
            elasticsearch_log_directory: Path to the elasticsearch log directory (E.G /var/log/dynamite/elasticsearch/)
            logstash_install_directory: Path to the logstash install directory (E.G /opt/dynamite/logstash/)
            logstash_configuration_directory: Path to the logstash configuration directory (E.G /etc/dynamite/logstash/)
            logstash_log_directory: Path to the log directory (E.G /var/log/dynamite/logstash/)
            kibana_install_directory: Path to the kibana install directory (E.G /opt/dynamite/kibana/)
            kibana_configuration_directory: Path to the kibana configuration directory (E.G /etc/dynamite/kibana/)
            kibana_log_directory: Path to the kibana configuration directory (E.G /var/log/dynamite/kibana/)
            stdout: Print output to console
            verbose: Include detailed debug messages
        """
        super().__init__('monitor.install', stdout=stdout, verbose=verbose)
        self.elasticsearch_install_directory = elasticsearch_install_directory
        self.elasticsearch_configuration_directory = elasticsearch_configuration_directory
        self.elasticsearch_log_directory = elasticsearch_log_directory
        self.logstash_install_directory = logstash_install_directory
        self.logstash_configuration_directory = logstash_configuration_directory
        self.logstash_log_directory = logstash_log_directory
        self.kibana_install_directory = kibana_install_directory
        self.kibana_configuration_directory = kibana_configuration_directory
        self.kibana_log_directory = kibana_log_directory

    def setup(self):
        """Setup Elasticsearch, Logstash, and Kibana
        Returns:
            None
        """

        if self.elasticsearch_install_directory or self.elasticsearch_configuration_directory or \
                self.elasticsearch_log_directory:
            if not (
                    self.elasticsearch_install_directory and self.elasticsearch_configuration_directory
                    and self.elasticsearch_log_directory
            ):
                self.logger.error(
                    'You must specify elasticsearch-configuration-directory, elasticsearch-install-directory, '
                    'and elasticsearch-log-directory.')
                return None
            elasticsearch_install.InstallManager(configuration_directory=self.elasticsearch_configuration_directory,
                                                 install_directory=self.elasticsearch_install_directory,
                                                 log_directory=self.elasticsearch_log_directory,
                                                 stdout=self.stdout, verbose=self.verbose).setup(
                node_name=utilities.get_default_es_node_name(), network_host=utilities.get_primary_ip_address(),
                port=9200)
        if self.logstash_install_directory or self.logstash_configuration_directory or self.logstash_log_directory:
            if not (
                    self.logstash_install_directory and self.logstash_configuration_directory
                    and self.logstash_log_directory
            ):
                self.logger.error(
                    'You must specify logstash-configuration-directory, logstash-install-directory, '
                    'and logstash-log-directory.')
                return None
            logstash_install.InstallManager(configuration_directory=self.logstash_configuration_directory,
                                            install_directory=self.logstash_install_directory,
                                            log_directory=self.logstash_log_directory,
                                            stdout=self.stdout, verbose=self.verbose).setup(
                node_name=utilities.get_default_es_node_name().replace('es', 'ls'),
                elasticsearch_host=utilities.get_primary_ip_address(), elasticsearch_port=9200)
        if self.kibana_install_directory or self.kibana_configuration_directory or self.kibana_log_directory:
            from dynamite_nsm.services.elasticsearch import process as elasticsearch_process
            if not (
                    self.kibana_install_directory and self.kibana_configuration_directory
                    and self.kibana_log_directory
            ):
                self.logger.error(
                    'You must specify kibana-configuration-directory, kibana-install-directory, '
                    'and kibana-log-directory.')
                return None
            self.logger.info('Starting Elasticsearch.')
            elasticsearch_process.ProcessManager().start()
            kibana_install.InstallManager(configuration_directory=self.kibana_configuration_directory,
                                          install_directory=self.kibana_install_directory,
                                          log_directory=self.kibana_log_directory,
                                          stdout=self.stdout, verbose=self.verbose).setup(
                host=utilities.get_primary_ip_address(), port=5601,
                elasticsearch_targets=[f'https://{utilities.get_primary_ip_address()}:9200'])


class UninstallManager(install.BaseUninstallManager):

    def __init__(self, stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """Uninstall Elasticsearch, Logstash, and Kibana
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
        """
        super().__init__(directories=[], name='monitor.uninstall', stdout=stdout, verbose=verbose)

    def uninstall(self):
        from dynamite_nsm.services.elasticsearch import profile as elasticsearch_profile
        from dynamite_nsm.services.logstash import profile as logstash_profile
        from dynamite_nsm.services.kibana import profile as kibana_profile

        if elasticsearch_profile.ProcessProfiler().is_installed():
            elasticsearch_install.UninstallManager(purge_config=True, stdout=self.stdout,
                                                   verbose=self.verbose).uninstall()
        if logstash_profile.ProcessProfiler().is_installed():
            logstash_install.UninstallManager(purge_config=True, stdout=self.stdout,
                                              verbose=self.verbose).uninstall()
        if kibana_profile.ProcessProfiler().is_installed():
            kibana_install.UninstallManager(purge_config=True, stdout=self.stdout, verbose=self.verbose).uninstall()
