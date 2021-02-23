import os
from typing import List, Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.services.base import install, systemctl
from dynamite_nsm.services.elasticsearch import config


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory: str, install_directory: str, log_directory: str,
                 download_elasticsearch_archive: Optional[bool] = True,
                 stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/elasticsearch/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/elasticsearch/)
        :param download_elasticsearch_archive: If True, download the ElasticSearch archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose

        install.BaseInstallManager.__init__(self, 'elasticsearch', verbose=self.verbose, stdout=stdout)

        self.logger.info("Attempting to download Elasticsearch (OpenDistro) archive.")
        self.url, \
        self.archive_name, \
        self.directory_name = self.download_from_mirror(const.ELASTICSEARCH_MIRRORS,
                                                        download_from_mirror=download_elasticsearch_archive,
                                                        stdout=stdout,
                                                        verbose=verbose)
        if download_elasticsearch_archive:
            self.logger.info(f'Attempting to extract Elasticsearch archive ({self.archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, self.archive_name))
        self.logger.info("Extraction completed.")

    def copy_elasticsearch_files_and_directories(self):
        elasticsearch_tarball_extracted = f'{const.INSTALL_CACHE}/{self.directory_name}'
        config_paths = [
            'config/elasticsearch.yml',
            'config/jvm.options',
            'config/log4j2.properties',
            'config/opendistro-reports-scheduler'
        ]
        install_paths = [
            'bin/',
            'data/',
            'lib/',
            'logs/',
            'modules/',
            'plugins/'
        ]
        for conf in config_paths:
            self.copy_file_or_directory_to_destination(f'{elasticsearch_tarball_extracted}/{conf}',
                                                       self.configuration_directory)
        for inst in install_paths:
            self.copy_file_or_directory_to_destination(f'{elasticsearch_tarball_extracted}/{inst}',
                                                       self.install_directory)

    def create_update_elasticsearch_environment_variables(self):
        self.create_update_env_variable('ES_PATH_CONF', self.configuration_directory)
        self.create_update_env_variable('ES_HOME', self.install_directory)
        self.create_update_env_variable('ES_LOGS', self.log_directory)

    def setup(self, node_name: Optional[str] = None, network_host: Optional[str] = None, port: Optional[int] = None,
              initial_master_nodes: Optional[List[str]] = None, discover_seed_hosts: Optional[List[str]] = None,
              heap_size_gigs: Optional[int] = None):
        """
        :param node_name: The name of this elasticsearch node
        :param network_host: The IP address to listen on (E.G "0.0.0.0")
        :param port: The port that the ES API is bound to (E.G 9200)
        :param initial_master_nodes: A list of nodes representing master (and master-eligible) nodes in this cluster
        :param discover_seed_hosts: A list of IPs on other hosts you wish to form a cluster with
        :param heap_size_gigs: The initial/max java heap space to allocate
        """
        sysctl = systemctl.SystemCtl()

        # System patching and directory setup
        utilities.update_sysctl()
        utilities.update_user_file_handle_limits()
        utilities.makedirs(self.configuration_directory)
        utilities.makedirs(self.install_directory)
        utilities.makedirs(self.log_directory)

        self.copy_elasticsearch_files_and_directories()
        self.create_update_elasticsearch_environment_variables()

        # Overwrite with dynamite default configurations
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/elasticsearch/elasticsearch.yml',
                                                   self.configuration_directory)
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/elasticsearch/jvm.options',
                                                   self.configuration_directory)

        # Optimize Configurations
        es_main_config = config.ConfigManager(self.configuration_directory)
        es_java_config = config.JavaHeapOptionsConfigManager(self.configuration_directory)
        es_main_config.path_logs = self.log_directory
        if not node_name:
            node_name = utilities.get_default_es_node_name()
        if not network_host:
            network_host = utilities.get_primary_ip_address()
        if not port:
            port = 9200
        if not initial_master_nodes:
            initial_master_nodes = [node_name]
        if not discover_seed_hosts:
            discover_seed_hosts = [network_host]
        if not heap_size_gigs:
            heap_size_gigs = int((utilities.get_memory_available_bytes() / 10 ** 9) / 2)

        es_main_config.node_name = node_name
        es_main_config.network_host = network_host
        es_main_config.http_port = port
        es_main_config.initial_master_nodes = initial_master_nodes
        es_main_config.seed_hosts = discover_seed_hosts
        es_java_config.initial_memory = f'{heap_size_gigs}g'
        es_java_config.maximum_memory = f'{heap_size_gigs}g'
        es_main_config.commit()
        es_java_config.commit()

        # Fix Permissions
        utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')

        # Install and enable service
        sysctl.install_and_enable(f'{const.DEFAULT_CONFIGS}/systemd/elasticsearch.service')


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory='/opt/dynamite/elasticsearch',
        configuration_directory='/etc/dynamite/elasticsearch',
        log_directory='/var/log/dynamite/elasticsearch/',
        download_elasticsearch_archive=True,
        stdout=True,
        verbose=True
    )
    install_mngr.setup()
