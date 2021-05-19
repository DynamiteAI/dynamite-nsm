import os
from typing import List, Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.jobs import events_to_hosts
from dynamite_nsm.services.base import install, systemctl
from dynamite_nsm.services.elasticsearch import config
from dynamite_nsm.services.elasticsearch.post_installation_tasks import post_install_bootstrap_tls_certificates, \
    post_install_bootstrap_cluster_settings


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory: str, install_directory: str, log_directory: str,
                 download_elasticsearch_archive: Optional[bool] = True,
                 stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """
        Install Elasticsearch

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
        install.BaseInstallManager.__init__(self, 'elasticsearch.install', verbose=self.verbose, stdout=stdout)
        java_home = self.dynamite_environ.get('JAVA_HOME')
        if not java_home:
            self.logger.info('Installing compatible version of Java.')
            from dynamite_nsm.services.java import install as java_install
            java_install.InstallManager(const.JVM_ROOT, stdout=stdout, verbose=verbose).setup()
        if download_elasticsearch_archive:
            self.logger.info("Attempting to download Elasticsearch (OpenDistro) archive.")
            _, archive_name, self.local_mirror_root = self.download_from_mirror(const.ELASTICSEARCH_MIRRORS)
            self.logger.info(f'Attempting to extract Elasticsearch archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.local_mirror_root = self.get_mirror_info(const.ELASTICSEARCH_MIRRORS)

    def copy_elasticsearch_files_and_directories(self) -> None:
        """
        Copy the required Elasticsearch files from the install cache to their respective directories
        """
        elasticsearch_tarball_extracted = f'{const.INSTALL_CACHE}/{self.local_mirror_root}'
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

    def create_update_elasticsearch_environment_variables(self) -> None:
        """
        Creates all the required ElasticSearch environmental variables
        """
        self.create_update_env_variable('ES_PATH_CONF', self.configuration_directory)
        self.create_update_env_variable('ES_HOME', self.install_directory)
        self.create_update_env_variable('ES_LOGS', self.log_directory)

    def setup(self, node_name: Optional[str] = None, network_host: Optional[str] = None, port: Optional[int] = None,
              initial_master_nodes: Optional[List[str]] = None, discover_seed_hosts: Optional[List[str]] = None,
              tls_cert_subject: Optional[str] = None, heap_size_gigs: Optional[int] = None):
        """
        :param node_name: The name of this elasticsearch node
        :param network_host: The IP address to listen on (E.G "0.0.0.0")
        :param port: The port that the ES API is bound to (E.G 9200)
        :param initial_master_nodes: A list of nodes representing master (and master-eligible) nodes in this cluster
        :param discover_seed_hosts: A list of IPs on other hosts you wish to form a cluster with
        :param tls_cert_subject: Denotes the thing being secured;
                                 E.G (/C=US/ST=GA/L=Atlanta/O=Dynamite Analytics/OU=R&D/CN=dynamite.ai)
        :param heap_size_gigs: The initial/max java heap space to allocate
        """
        sysctl = systemctl.SystemCtl()

        # System patching and directory setup
        self.logger.debug('Patching sysctl.')
        utilities.update_sysctl()
        self.logger.debug('Patching file-handle limits.')
        utilities.update_user_file_handle_limits()

        self.logger.debug(f'Creating directory: {self.configuration_directory}')
        utilities.makedirs(self.configuration_directory)
        self.logger.debug(f'Creating directory: {self.install_directory}')
        utilities.makedirs(self.install_directory)
        self.logger.debug(f'Creating directory: {self.log_directory}')
        utilities.makedirs(self.log_directory)

        self.copy_elasticsearch_files_and_directories()
        self.create_update_elasticsearch_environment_variables()

        # Overwrite with dynamite default configurations
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/elasticsearch/elasticsearch.yml',
                                                   self.configuration_directory)
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/elasticsearch/jvm.options',
                                                   self.configuration_directory)
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/elasticsearch/security',
                                                   self.configuration_directory)

        # Optimize Configurations
        es_main_config = config.ConfigManager(self.configuration_directory, verbose=self.verbose, stdout=self.stdout)
        es_java_config = config.JavaHeapOptionsConfigManager(self.configuration_directory, verbose=self.verbose,
                                                             stdout=self.stdout)
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
        if not tls_cert_subject:
            tls_cert_subject = '/C=US/ST=GA/L=Atlanta/O=Dynamite/OU=R&D/CN=dynamite.ai'
        else:
            tls_cert_subject = tls_cert_subject
        if not heap_size_gigs:
            heap_size_gigs = int((utilities.get_memory_available_bytes() / 10 ** 9) / 2)
        formatted_subj = tls_cert_subject.lstrip("/").replace("/", ",")
        formatted_subj_2 = ','.join(reversed(formatted_subj.split(',')))
        es_main_config.node_name = node_name
        es_main_config.network_host = network_host
        es_main_config.http_port = port
        es_main_config.initial_master_nodes = initial_master_nodes
        es_main_config.seed_hosts = discover_seed_hosts
        es_main_config.authcz_admin_distinguished_names = [formatted_subj, formatted_subj_2]
        es_java_config.initial_memory = f'{heap_size_gigs}g'
        es_java_config.maximum_memory = f'{heap_size_gigs}g'
        self.logger.debug(f'Java Heap Initial & Max Memory = {heap_size_gigs} GB')
        es_main_config.commit()
        es_java_config.commit()
        self.logger.info('Applying configuration.')

        # Fix Permissions
        self.logger.info('Setting up file permissions.')
        utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')

        # Install and enable service
        self.logger.info(f'Installing service -> {const.DEFAULT_CONFIGS}/systemd/elasticsearch.service')
        sysctl.install_and_enable(f'{const.DEFAULT_CONFIGS}/systemd/elasticsearch.service')

        # Bootstrap Transport Layer Security
        self.logger.info('Beginning TLS bootstrapping process.')
        post_install_bootstrap_tls_certificates(self.configuration_directory, self.install_directory,
                                                subj=tls_cert_subject, stdout=self.stdout,
                                                verbose=self.verbose)
        self.logger.info('Begin cluster settings bootstrapping process.')
        post_install_bootstrap_cluster_settings(stdout=self.stdout, verbose=self.verbose)
        self.logger.info('Install events_to_hosts job.')
        event_to_host_job = events_to_hosts.EventsToHostsJob('admin', 'admin', target=f'https://{network_host}:{port}')
        event_to_host_job.download_and_install()
        event_to_host_job.create_cronjob()


class UninstallManager(install.BaseUninstallManager):
    """
    Uninstall Elasticsearch
    """

    def __init__(self, purge_config: Optional[bool] = True, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """
        :param purge_config: If enabled, remove all the configuration files associated with this installation
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """
        from dynamite_nsm.services.elasticsearch.config import ConfigManager
        from dynamite_nsm.services.elasticsearch.process import ProcessManager

        env_vars = utilities.get_environment_file_dict()
        es_config = ConfigManager(configuration_directory=env_vars.get('ES_PATH_CONF'))
        es_directories = [env_vars.get('ES_HOME'), es_config.path_logs]
        if purge_config:
            es_directories.append(env_vars.get('ES_PATH_CONF'))
        super().__init__('elasticsearch.uninstall', directories=es_directories,
                         environ_vars=['ES_PATH_CONF', 'ES_HOME', 'ES_LOG'],
                         process=ProcessManager(stdout=stdout, verbose=verbose),
                         sysctl_service_name='elasticsearch.service', stdout=stdout, verbose=verbose)

    if __name__ == '__main__':
        install_mngr = InstallManager(
            install_directory=f'{const.INSTALL_PATH}/elasticsearch',
            configuration_directory=f'{const.CONFIG_PATH}/elasticsearch',
            log_directory=f'{const.LOG_PATH}/elasticsearch',
            download_elasticsearch_archive=True,
            stdout=True,
            verbose=True
        )
        install_mngr.setup()
