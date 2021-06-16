import logging
from time import sleep
from typing import Optional
from subprocess import Popen, PIPE
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger


def post_install_bootstrap_tls_certificates(configuration_directory: str, install_directory: str,
                                            cert_name: Optional[str] = 'admin.pem',
                                            key_name: Optional[str] = 'admin-key.pem',
                                            subj: Optional[str] =
                                            '/C=US/ST=GA/L=Atlanta/O=Dynamite/OU=R&D/CN=dynamite.ai',
                                            trusted_ca_cert_name: Optional[str] = 'root-ca.pem',
                                            trusted_ca_key_name: Optional[str] = 'root-ca-key.pem',
                                            bootstrap_attempts: Optional[int] = 10,
                                            stdout: Optional[bool] = False,
                                            verbose: Optional[bool] = False) -> None:
    """Used to setup self-signed node-node dnd REST API TLS encryption after installation
    Args:
        configuration_directory: Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
        install_directory: Path to the install directory (E.G /opt/dynamite/elasticsearch/)
        cert_name: The name of the certificate file
        key_name: The name of the key file
        subj: The certificate subj parameters section (E.G '/C=US/ST=GA/L=Atlanta/O=Dynamite/OU=R&D/CN=dynamite.ai')
        trusted_ca_cert_name: The name of the trusted CA cert
        trusted_ca_key_name: The name of the trusted CA key
        bootstrap_attempts: The maximum number attempts before giving up on bootstrapping
        stdout: Print output to console
        verbose: Include detailed debug messages
    Returns:
        None
    """
    from dynamite_nsm.services.elasticsearch import config, process, profile
    es_process_profile = profile.ProcessProfiler()
    opendistro_security_tools_directory = f'{install_directory}/plugins/opendistro_security/tools'
    opendistro_security_admin = f'{opendistro_security_tools_directory}/securityadmin.sh'
    utilities.set_permissions_of_file(file_path=opendistro_security_admin, unix_permissions_integer='+x')
    security_conf_directory = f'{configuration_directory}/security'
    cert_directory = f'{security_conf_directory}/auth'
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('elasticsearch.tls_setup', level=log_level, stdout=stdout)

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
    utilities.set_permissions_of_file(file_path=cert_directory, unix_permissions_integer=700)
    utilities.set_permissions_of_file(file_path=f'{cert_directory}/{cert_name}', unix_permissions_integer=600)
    utilities.set_permissions_of_file(file_path=f'{cert_directory}/{key_name}', unix_permissions_integer=600)
    utilities.set_permissions_of_file(file_path=f'{cert_directory}/{trusted_ca_cert_name}',
                                      unix_permissions_integer=600)
    utilities.set_permissions_of_file(file_path=f'{cert_directory}/{trusted_ca_key_name}', unix_permissions_integer=600)
    logger.info('Starting ElasticSearch process to install our security index configuration.')
    process.ProcessManager(stdout=stdout, verbose=verbose).start()

    es_main_config = config.ConfigManager(configuration_directory)
    network_host = es_main_config.network_host
    es_main_config.transport_pem_cert_file = f'security/auth/{cert_name}'
    es_main_config.rest_api_pem_cert_file = es_main_config.transport_pem_cert_file

    es_main_config.transport_pem_key_file = f'security/auth/{key_name}'
    es_main_config.rest_api_pem_key_file = es_main_config.transport_pem_key_file

    es_main_config.transport_trusted_cas_file = f'security/auth/{trusted_ca_cert_name}'
    es_main_config.rest_api_trusted_cas_file = es_main_config.transport_trusted_cas_file
    es_main_config.commit()
    attempts = 0
    if not es_process_profile.is_running():
        logger.warning(f'Could not start Elasticsearch cluster. Check the Elasticsearch cluster log.')
        return
    while not es_process_profile.is_listening() and attempts < bootstrap_attempts:
        logger.info(f'Waiting for Elasticsearch API to become available - attempt {attempts + 1}.')
        attempts += 1
        sleep(10)
    security_admin_args = ['-diagnose', '-icl', '-nhnv', '-cacert',
                           f'{cert_directory}/root-ca.pem', '-cert', f'{cert_directory}/admin.pem', '-key',
                           f'{cert_directory}/admin-key.pem', '--hostname', network_host, '--port', '9300']
    logger.debug(f'{opendistro_security_admin} {" ".join(security_admin_args)}')

    p = Popen(executable=opendistro_security_admin, args=security_admin_args,
              stdout=PIPE, stderr=PIPE, cwd=security_conf_directory, env=utilities.get_environment_file_dict())
    out, err = p.communicate()
    if p.returncode != 0:
        logger.warning(
            f'TLS bootstrapping failed while installing initial security configuration with the following error: {err} '
            f'| {out}. You may need to do this step manually after the cluster has been started: '
            f'{opendistro_security_admin} {" ".join(security_admin_args)}'
        )
    else:
        logger.info(f'Bootstrapping security successful. You can find the current certs/keys here: {cert_directory}')
    logger.info('Shutting down ElasticSearch service.')
    process.ProcessManager(stdout=stdout, verbose=verbose).stop()


def post_install_bootstrap_cluster_settings(bootstrap_attempts: Optional[int] = 10, stdout: Optional[bool] = False,
                                            verbose: Optional[bool] = False):
    """Updates various settings in the _cluster API
    Args:
        bootstrap_attempts: The maximum number attempts before giving up on bootstrapping
        stdout: Print output to console
        verbose: Include detailed debug messages
    Returns:
        None
    """
    import json
    import requests
    from dynamite_nsm.services.elasticsearch import process, profile
    es_process_profile = profile.ProcessProfiler()
    log_level = logging.INFO
    es_url = f'https://{utilities.get_primary_ip_address()}:9200'
    es_cluster_data = {'persistent': {'script.max_compilations_rate': '1000/5m'},
                       'transient': {'script.max_compilations_rate': '1000/5m'}}
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('elasticsearch.cluster_setup', level=log_level, stdout=stdout)
    logger.info('Starting ElasticSearch process to update cluster settings.')
    process.ProcessManager(stdout=stdout, verbose=verbose).start()
    attempts = 0
    if not es_process_profile.is_running():
        logger.warning(f'Could not start Elasticsearch cluster. Check the Elasticsearch cluster log.')
        return
    while not es_process_profile.is_listening() and attempts < bootstrap_attempts:
        logger.info(f'Waiting for Elasticsearch API to become available - attempt {attempts + 1}.')
        attempts += 1
        sleep(10)
    logger.info(f'Updating cluster settings on {es_url}')
    r = requests.put(
        url=f'{es_url}/_cluster/settings',
        data=json.dumps(es_cluster_data),
        auth=('admin', 'admin'),
        headers={'content-type': 'application/json'},
        verify=False
    )
    logger.debug(r.text)
    if r.status_code != 200:
        logger.warning(
            f"Cluster settings failed to update. "
            f"You can install these settings yourself via: curl -X PUT --insecure {es_url}/_cluster/settings "
            f"-u admin:admin -d '{json.dumps(es_cluster_data)}' -H \'Content-Type: application/json\'"
        )
    else:
        logger.info(f'Bootstrapping cluster settings successful.')
    logger.info('Shutting down ElasticSearch service.')
    process.ProcessManager(stdout=stdout, verbose=verbose).stop()


def post_install_bootstrap_index_aliases(bootstrap_attempts: Optional[int] = 10, stdout: Optional[bool] = False,
                                         verbose: Optional[bool] = False):
    """
    Updates various settings in the _aliases API

    :param bootstrap_attempts: The maximum number attempts before giving up on bootstrapping
    :param stdout: Print output to console
    :param verbose: Include detailed debug messages
    """
    import json, requests
    from dynamite_nsm.services.elasticsearch import process, profile
    es_process_profile = profile.ProcessProfiler()
    log_level = logging.INFO
    es_url = f'https://{utilities.get_primary_ip_address()}:9200'
    es_index_data = {'actions': {'add': {'index': 'filebeat-*', 'alias': 'dynamite-*'}}}
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('elasticsearch.index_setup', level=log_level, stdout=stdout)
    logger.info('Starting ElasticSearch process to update index aliases.')
    process.ProcessManager(stdout=stdout, verbose=verbose).start()
    attempts = 0
    if not es_process_profile.is_running():
        logger.warning(f'Could not start Elasticsearch cluster. Check the Elasticsearch cluster log.')
        return
    while not es_process_profile.is_listening() and attempts < bootstrap_attempts:
        logger.info(f'Waiting for Elasticsearch API to become available - attempt {attempts + 1}.')
        attempts += 1
        sleep(10)
    logger.info(f'Updating index alias settings on {es_url}')
    r = requests.post(
        url=f'{es_url}/_aliases',
        data=json.dumps(es_index_data),
        auth=('admin', 'admin'),
        headers={'content-type': 'application/json'},
        verify=False
    )
    logger.debug(r.text)
    if r.status_code not in [200, 201]:
        logger.warning(
            f"Index settings failed to update. "
            f"You can install these settings yourself via: curl -X POST --insecure {es_url}/_aliases "
            f"--user: admin:admin -d '{json.dumps(es_index_data)}'"
        )
    else:
        logger.info(f'Bootstrapping index settings successful.')
    logger.info('Shutting down ElasticSearch service.')
    process.ProcessManager(stdout=stdout, verbose=verbose).stop()
