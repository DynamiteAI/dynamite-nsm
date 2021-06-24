from typing import Optional

import bcrypt
from yaml import Loader
from yaml import load

from dynamite_nsm.services.elasticsearch.tasks import setup_security
from dynamite_nsm.services.base.config import JavaOptionsConfigManager, YamlConfigManager


class ConfigManager(YamlConfigManager):

    def __init__(self, configuration_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """Manage an Elasticsearch configuration
        Args:
            configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
            stdout: Print output to console
            verbose: Include detailed debug messages
        """
        extract_tokens = {
            'node_name': ('node.name',),
            'cluster_name': ('cluster.name',),
            'seed_hosts': ('discovery.seed_hosts',),
            'initial_master_nodes': ('cluster.initial_master_nodes',),
            'network_host': ('network.host',),
            'http_port': ('http.port',),
            'path_data': ('path.data',),
            'path_logs': ('path.logs',),
            'search_max_buckets': ('search.max_buckets',),
            'transport_pem_cert_file': ('opendistro_security.ssl.transport.pemcert_filepath',),
            'transport_pem_key_file': ('opendistro_security.ssl.transport.pemkey_filepath',),
            'transport_trusted_cas_file': ('opendistro_security.ssl.transport.pemtrustedcas_filepath',),
            'rest_api_pem_cert_file': ('opendistro_security.ssl.http.pemcert_filepath',),
            'rest_api_pem_key_file': ('opendistro_security.ssl.http.pemkey_filepath',),
            'rest_api_trusted_cas_file': ('opendistro_security.ssl.http.pemtrustedcas_filepath',),
            'authcz_admin_distinguished_names': ('opendistro_security.authcz.admin_dn',)
        }
        self.node_name = None
        self.cluster_name = None
        self.seed_hosts = None
        self.initial_master_nodes = None
        self.network_host = None
        self.http_port = None
        self.path_logs = None
        self.search_max_buckets = None
        self.rest_api_pem_cert_file = None
        self.rest_api_pem_key_file = None
        self.rest_api_trusted_cas_file = None
        self.transport_pem_cert_file = None
        self.transport_pem_cert_file = None
        self.transport_pem_key_file = None
        self.transport_trusted_cas_file = None
        self.authcz_admin_distinguished_names = None
        self.configuration_directory = configuration_directory
        self.elasticsearch_config_path = f'{self.configuration_directory}/elasticsearch.yml'

        with open(self.elasticsearch_config_path) as configyaml:
            self.config_data_raw = load(configyaml, Loader=Loader)
        super().__init__(self.config_data_raw, name='elasticsearch.config', verbose=verbose, stdout=stdout,
                         **extract_tokens)
        self.parse_yaml_file()

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None,
               top_text: Optional[str] = None) -> None:
        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file; if none given overwrites existing
            backup_directory: The path to the backup directory
            top_text: The very first line of the YAML file
        Returns:
            None
        """
        if not out_file_path:
            out_file_path = self.elasticsearch_config_path

        super(ConfigManager, self).commit(out_file_path, backup_directory)


class ChangePasswordManager(YamlConfigManager):

    def __init__(self, configuration_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """Manage an Elasticsearch internal users passwords
        Args:
            configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
            stdout: Print output to console
            verbose: Include detailed debug messages
        """
        self.configuration_directory = configuration_directory
        self.elasticsearch_config_path = f'{self.configuration_directory}/security/internal_users.yml'

        extract_tokens = {
            '_admin_hash': ('admin', 'hash'),
            '_kibanaserver_hash': ('kibanaserver', 'hash'),
            '_kibanaro_hash': ('kibanaro', 'hash'),
            '_logstash_hash': ('logstash', 'hash'),
            '_readall_hash': ('readall', 'hash'),
            '_snapshotrestore_hash': ('snapshotrestore', 'hash')
        }

        self._admin_hash = None
        self._kibanaserver_hash = None
        self._kibanaro_hash = None
        self._logstash_hash = None
        self._readall_hash = None
        self._snapshotrestore_hash = None

        self.admin = 'Hidden'
        self.kibana_server = 'Hidden'
        self.kibana_readonly = 'Hidden'
        self.logstash = 'Hidden'
        self.readall = 'Hidden'
        self.snapshot_restore = 'Hidden'
        with open(self.elasticsearch_config_path) as configyaml:
            self.config_data_raw = load(configyaml, Loader=Loader)
        super().__init__(self.config_data_raw, name='elasticsearch.chpasswd', verbose=verbose, stdout=stdout,
                         **extract_tokens)
        self.parse_yaml_file()

    @staticmethod
    def hash_plaintext(password_string: str) -> str:
        password_bytes = str.encode(password_string)
        hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12, prefix=b'2a'))
        return hashed.decode()

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None,
               top_text: Optional[str] = None) -> None:
        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file; if none given overwrites existing
            backup_directory: The path to the backup directory
            top_text: The very first line of the YAML file
        Returns:
            None
        """
        if not out_file_path:
            out_file_path = self.elasticsearch_config_path

        if self.admin != 'Hidden':
            self._admin_hash = self.hash_plaintext(self.admin)
        if self.kibana_server != 'Hidden':
            self._kibanaserver_hash = self.hash_plaintext(self.kibana_server)
        if self.kibana_readonly != 'Hidden':
            self._kibanaro_hash = self.hash_plaintext(self.kibana_readonly)
        if self.logstash != 'Hidden':
            self._logstash_hash = self.hash_plaintext(self.logstash)
        if self.snapshot_restore != 'Hidden':
            self._snapshotrestore_hash = self.hash_plaintext(self.snapshot_restore)

        super(ChangePasswordManager, self).commit(out_file_path, backup_directory)
        main_config = ConfigManager(self.configuration_directory)
        self.logger.warning('Cycling Elasticsearch service in order for changes to take effect.')
        setup_security.InstallElasticsearchCertificates(network_host=main_config.network_host,
                                                        terminate_elasticsearch=False).invoke()


class JavaHeapOptionsConfigManager(JavaOptionsConfigManager):

    def __init__(self, configuration_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """Configure Elasticsearch Java Heap Options
        Args:
            configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
            stdout: Print output to console
            verbose: Include detailed debug messages
        """

        self.configuration_directory = configuration_directory
        self.elasticsearch_jvm_config_path = f'{self.configuration_directory}/jvm.options'
        with open(self.elasticsearch_jvm_config_path) as jvm_config:
            data = {'data': jvm_config.readlines()}
        super().__init__(data, name='elasticsearch.java', verbose=verbose, stdout=stdout)

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file; if none given overwrites existing
            backup_directory: The path to the backup directory
        """
        if not out_file_path:
            out_file_path = self.elasticsearch_jvm_config_path
        super(JavaHeapOptionsConfigManager, self).commit(out_file_path, backup_directory)
