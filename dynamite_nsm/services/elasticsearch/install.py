import logging
import os
from subprocess import Popen, PIPE
from typing import List, Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.base import install, systemctl
from dynamite_nsm.services.elasticsearch import config


def post_install_bootstrap_tls_certificates(configuration_directory: str, install_directory: str,
                                            cert_name: Optional[str] = 'admin.pem',
                                            key_name: Optional[str] = 'admin-key.pem',
                                            subj: Optional[str] =
                                            '/C=US/ST=GA/L=Atlanta/O=Dynamite Analytics/OU=R&D/CN=dynamite.ai',
                                            trusted_ca_cert_name: Optional[str] = 'root-ca.pem',
                                            trusted_ca_key_name: Optional[str] = 'root-ca-key.pem',
                                            stdout: Optional[bool] = False,
                                            verbose: Optional[bool] = False):
    from dynamite_nsm.services.elasticsearch import process
    opendistro_security_tools_directory = f'{install_directory}/plugins/opendistro_security/tools/'
    cert_directory = f'{configuration_directory}/security/auth/'
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('ELASTICSEARCH_TLS_BOOTSTRAPPER', level=log_level, stdout=stdout)

    utilities.makedirs(f'{cert_directory}')
    openssl_commands = [
        (['genrsa', '-out', 'root-ca-key.pem', '2048'], 'Generating a private key.'),

        (['req', '-new', '-x509', '-sha256', '-key', 'root-ca-key.pem', '-out', 'root-ca.pem', '-subj', subj],
         'Generating a self-signed root certificate'),

        (['genrsa', '-out', 'admin-key-temp.pem', '2048'], 'Generating an admin certificate temporary key.'),

        (['pkcs8', '-inform', 'PEM', '-outform', 'PEM', '-in', 'admin-key-temp.pem', '-topk8', '-nocrypt', '-v1',
          'PBE-SHA1-3DES', '-out', 'admin-key.pem'], 'Converting key to PKCS#8 format.'),

        (['req', '-new', '-key', key_name, '-out', 'admin.csr', '-subj', subj],
         'Creating a certificate signing request (CSR).'),

        (['x509', '-req', '-in', 'admin.csr', '-CA', trusted_ca_cert_name, '-CAkey', trusted_ca_key_name,
          '-CAcreateserial',
          '-sha256', '-out', cert_name], 'Generating the certificate itself'),
    ]

    for argument_group, description in openssl_commands:
        logger.info(description)
        logger.debug(f'openssl {" ".join(argument_group)}')
        p = Popen(executable='openssl', args=argument_group, stdout=PIPE, stderr=PIPE, cwd=cert_directory)
        out, err = p.communicate()
        if p.returncode != 0:
            logger.warning(f'TLS bootstrapping failed. You may need to do this step manually: {err}')
    utilities.safely_remove_file(f'{cert_directory}/admin-key-temp.pem')
    utilities.safely_remove_file(f'{cert_directory}/admin.csr')
    utilities.set_ownership_of_file(path=cert_directory, user='dynamite', group='dynamite')
    logger.info('Starting ElasticSearch process to install our security index configuration.')
    process.start(stdout=stdout, verbose=verbose)
    network_host = config.ConfigManager(configuration_directory).network_host
    security_admin_args = [f'{opendistro_security_tools_directory}/securityadmin.sh', '-icl', '-nhnv', '-cacert',
                           f'{cert_directory}/root-ca.pem', '-cert', f'{cert_directory}/admin.pem', '-key',
                           f'{cert_directory}/admin-key.pem', '--hostname', network_host, '--port', '9300']
    logger.debug(f'bash {" ".join(security_admin_args)}')
    p = Popen(executable='bash', args=security_admin_args, stdout=PIPE, stderr=PIPE,
              env=utilities.get_environment_file_dict(), shell=True)
    out, err = p.communicate()
    if p.returncode != 0:
        logger.warning(
            f'TLS bootstrapping failed while installing initial security configuration. '
            f'You may need to do this step manually: {err}')
    process.stop(stdout=stdout, verbose=verbose)


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

        if download_elasticsearch_archive:
            self.logger.info("Attempting to download Elasticsearch (OpenDistro) archive.")
            _, archive_name, self.directory_name = self.download_from_mirror(const.ELASTICSEARCH_MIRRORS,
                                                                             stdout=stdout, verbose=verbose)
            self.logger.info(f'Attempting to extract Elasticsearch archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.directory_name = self.get_mirror_info(const.ELASTICSEARCH_MIRRORS)

    def copy_elasticsearch_files_and_directories(self) -> None:
        """
        Copy the required Elasticsearch files from the install cache to their respective directories
        """
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
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/elasticsearch/security',
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
        if not tls_cert_subject:
            tls_cert_subject = 'C=US,ST=GA,L=Atlanta,O=Dynamite Analytics,OU=R&D,CN=dynamite.ai'
        else:
            tls_cert_subject = tls_cert_subject.lstrip('/').replace('/', ',')
        if not heap_size_gigs:
            heap_size_gigs = int((utilities.get_memory_available_bytes() / 10 ** 9) / 2)

        es_main_config.node_name = node_name
        es_main_config.network_host = network_host
        es_main_config.http_port = port
        es_main_config.initial_master_nodes = initial_master_nodes
        es_main_config.seed_hosts = discover_seed_hosts
        es_main_config.authcz_admin_distinguished_names = [tls_cert_subject]
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

        # Bootstrap Transport Layer Security
        self.logger.info('Beginning TLS bootstrapping process.')
        post_install_bootstrap_tls_certificates(self.configuration_directory, self.install_directory,
                                                subj=tls_cert_subject, stdout=self.stdout,
                                                verbose=self.verbose)


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/elasticsearch',
        configuration_directory=f'{const.CONFIG_PATH}/elasticsearch',
        log_directory=f'{const.LOG_PATH}/elasticsearch',
        download_elasticsearch_archive=False,
        stdout=True,
        verbose=True
    )
    install_mngr.setup()
