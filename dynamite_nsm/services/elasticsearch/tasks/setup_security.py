from time import sleep
from typing import List, Optional, Tuple

from dynamite_nsm import utilities
from dynamite_nsm.services.base import tasks
from dynamite_nsm.services.elasticsearch import config
from dynamite_nsm.services.elasticsearch import process
from dynamite_nsm.services.elasticsearch import profile


class GenerateElasticsearchSSLCertificates(tasks.BaseShellCommandsTask):

    def __init__(self,
                 cert_name: Optional[str] = 'admin.pem',
                 key_name: Optional[str] = 'admin-key.pem',
                 subj: Optional[str] =
                 '/C=US/ST=GA/L=Atlanta/O=Dynamite/OU=R&D/CN=dynamite.ai',
                 trusted_ca_cert_name: Optional[str] = 'root-ca.pem',
                 trusted_ca_key_name: Optional[str] = 'root-ca-key.pem'):
        env = utilities.get_environment_file_dict()
        self.configuration_directory = env.get('ES_PATH_CONF')
        self.cert_name = cert_name
        self.key_name = key_name
        self.subj = subj
        self.trusted_ca_cert_name = trusted_ca_cert_name
        self.trusted_ca_key_name = trusted_ca_key_name
        self.security_conf_directory = f'{self.configuration_directory}/security'
        self.cert_directory = f'{self.security_conf_directory}/auth'

        super(GenerateElasticsearchSSLCertificates, self).__init__(
            name='generate_elasticsearch_certificates', package_link='N/A',
            commands=[
                ['openssl', 'genrsa', '-out', trusted_ca_key_name, '2048'],
                ['openssl', 'req', '-new', '-x509', '-sha256', '-key', trusted_ca_key_name, '-out',
                 trusted_ca_cert_name,
                 '-subj', subj],
                ['openssl', 'genrsa', '-out', 'admin-key-temp.pem', '2048'],
                ['openssl', 'pkcs8', '-inform', 'PEM', '-outform', 'PEM', '-in', 'admin-key-temp.pem', '-topk8',
                 '-nocrypt', '-v1', 'PBE-SHA1-3DES', '-out', key_name],
                ['openssl', 'req', '-new', '-key', key_name, '-out', 'admin.csr', '-subj', subj],
                ['openssl', 'x509', '-req', '-in', 'admin.csr', '-CA', trusted_ca_cert_name, '-CAkey',
                 trusted_ca_key_name, '-CAcreateserial', '-sha256', '-out', cert_name],
            ])

    def invoke(self, shell: Optional[bool] = False, cwd: Optional[str] = None) -> \
            List[Tuple[List, bytes, bytes]]:
        utilities.makedirs(f'{self.cert_directory}')
        if not cwd:
            cwd = self.cert_directory
        results = super().invoke(shell=shell, cwd=cwd)
        utilities.safely_remove_file(f'{self.cert_directory}/admin-key-temp.pem')
        utilities.safely_remove_file(f'{self.cert_directory}/admin.csr')
        utilities.set_ownership_of_file(path=self.cert_directory, user='dynamite', group='dynamite')
        utilities.set_permissions_of_file(file_path=self.cert_directory, unix_permissions_integer=700)
        utilities.set_permissions_of_file(file_path=f'{self.cert_directory}/{self.cert_name}',
                                          unix_permissions_integer=600)
        utilities.set_permissions_of_file(file_path=f'{self.cert_directory}/{self.key_name}',
                                          unix_permissions_integer=600)
        utilities.set_permissions_of_file(file_path=f'{self.cert_directory}/{self.trusted_ca_cert_name}',
                                          unix_permissions_integer=600)
        utilities.set_permissions_of_file(file_path=f'{self.cert_directory}/{self.trusted_ca_key_name}',
                                          unix_permissions_integer=600)
        es_main_config = config.ConfigManager(self.configuration_directory)
        es_main_config.transport_pem_cert_file = f'security/auth/{self.cert_name}'
        es_main_config.rest_api_pem_cert_file = es_main_config.transport_pem_cert_file

        es_main_config.transport_pem_key_file = f'security/auth/{self.key_name}'
        es_main_config.rest_api_pem_key_file = es_main_config.transport_pem_key_file

        es_main_config.transport_trusted_cas_file = f'security/auth/{self.trusted_ca_cert_name}'
        es_main_config.rest_api_trusted_cas_file = es_main_config.transport_trusted_cas_file
        es_main_config.commit()
        return results


class InstallElasticsearchCertificates(tasks.BaseShellCommandsTask):

    def __init__(self, network_host: str, max_attempts: Optional[int] = 10,
                 terminate_elasticsearch: Optional[bool] = True):
        env = utilities.get_environment_file_dict()
        configuration_directory = env.get('ES_PATH_CONF')
        install_directory = env.get('ES_HOME')
        self.security_conf_directory = f'{configuration_directory}/security'
        self.cert_directory = f'{self.security_conf_directory}/auth'
        self.max_attempts = max_attempts
        self.opendistro_security_tools_directory = f'{install_directory}/plugins/opendistro_security/tools'
        self.opendistro_security_admin = f'{self.opendistro_security_tools_directory}/securityadmin.sh'
        self.terminate_elasticsearch = terminate_elasticsearch

        super(InstallElasticsearchCertificates, self).__init__(
            name='install_elasticsearch_certificates', package_link='N/A',
            commands=[
                [self.opendistro_security_admin, '-diagnose', '-icl', '-nhnv', '-cacert',
                 f'{self.cert_directory}/root-ca.pem',
                 '-cert', f'{self.cert_directory}/admin.pem', '-key', f'{self.cert_directory}/admin-key.pem',
                 '--hostname', network_host, '--port', '9300']
            ])

    def invoke(self, shell: Optional[bool] = False, cwd: Optional[str] = None) -> List[
        Tuple[List, bytes, bytes]]:
        utilities.set_permissions_of_file(file_path=self.opendistro_security_admin, unix_permissions_integer='+x')
        if not cwd:
            cwd = self.security_conf_directory
        attempts = 0
        es_process_profile = profile.ProcessProfiler()
        if not es_process_profile.is_listening():
            process.ProcessManager().start()
        while not es_process_profile.is_listening() and attempts < self.max_attempts:
            attempts += 1
            sleep(10)
        results = super().invoke(shell, cwd)
        if self.terminate_elasticsearch:
            process.ProcessManager().stop()
        return results


if __name__ == '__main__':
    GenerateElasticsearchSSLCertificates().invoke()
    res = InstallElasticsearchCertificates(network_host=utilities.get_primary_ip_address()).invoke()
    print(res)
