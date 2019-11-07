import os
import sys
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities

INSTALL_DIRECTORY = '/etc/dynamite/logstash/elastiflow/'


class ElastiflowConfigurator:
    """
    A configuration interface for ElastiFlow
    """
    def __init__(self):
        self.es_passwd = 'changeme'
        self.netflow_ipv4_host = '0.0.0.0'
        self.netflow_ipv6_host = '[::]'
        self.netflow_ipv4_port = 2055
        self.netflow_ipv6_port = 56343
        self.sflow_ipv4_host = '0.0.0.0'
        self.sflow_ipv6_host = '[::]'
        self.sflow_ipv4_port = 6343
        self.sflow_ipv6_port = 54739
        self.ipfix_tcp_ipv4_host = '0.0.0.0'
        self.ipfix_tcp_ipv6_host = '[::]'
        self.ipfix_tcp_ipv4_port = 4739
        self.ipfix_tcp_ipv6_port = 54739
        self.ipfix_udp_ipv4_host = '0.0.0.0'
        self.ipfix_udp_ipv6_host = '[::]'
        self.ipfix_udp_ipv4_port = 4739
        self.ipfix_udp_ipv6_port = 54739
        self.zeek_ipv4_host = '0.0.0.0'
        self.zeek_ipv4_port = 5044

        self.netflow_udp_workers = 4
        self.netflow_udp_queue_size = 4096
        self.netflow_udp_rcv_buff = 33554432
        self.sflow_udp_workers = 4
        self.sflow_udp_queue_size = 4096
        self.sflow_udp_rcv_buff = 33554432
        self.ipfix_udp_workers = 4
        self.ipfix_udp_queue_size = 4096
        self.ipfix_udp_rcv_buff = 33554432

        self.es_host = '127.0.0.1:9200'
        self._parse_environment_file()

    def _parse_environment_file(self):
        """
        Parses the /etc/dynamite/environment file and returns ElastiFlow configurations;
        stores the results in class variables of the same name
        """
        for line in open('/etc/dynamite/environment').readlines():
            if line.startswith('ELASTIFLOW_ES_PASSWD'):
                self.es_passwd = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_NETFLOW_IPV4_HOST'):
                self.netflow_ipv4_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_NETFLOW_IPV4_PORT'):
                self.netflow_ipv4_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_SFLOW_IPV4_HOST'):
                self.sflow_ipv4_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_SFLOW_IPV4_PORT'):
                self.sflow_ipv4_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_TCP_IPV4_HOST'):
                self.ipfix_tcp_ipv4_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_TCP_IPV4_PORT'):
                self.ipfix_tcp_ipv4_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_UDP_IPV4_HOST'):
                self.ipfix_udp_ipv4_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_UDP_IPV4_PORT'):
                self.ipfix_udp_ipv4_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_NETFLOW_IPV6_HOST'):
                self.netflow_ipv6_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_NETFLOW_IPV6_PORT'):
                self.netflow_ipv6_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_SFLOW_IPV6_HOST'):
                self.sflow_ipv6_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_SFLOW_IPV6_PORT'):
                self.sflow_ipv6_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_TCP_IPV6_HOST'):
                self.ipfix_tcp_ipv6_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_TCP_IPV6_PORT'):
                self.ipfix_tcp_ipv6_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_UDP_IPV6_HOST'):
                self.ipfix_udp_ipv6_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_UDP_IPV6_PORT'):
                self.ipfix_udp_ipv6_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_ZEEK_HOST'):
                self.zeek_ipv4_host = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_ZEEK_PORT'):
                self.zeek_ipv4_port = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_NETFLOW_UDP_WORKERS'):
                self.netflow_udp_workers = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_NETFLOW_UDP_QUEUE_SIZE'):
                self.netflow_udp_queue_size = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_NETFLOW_UDP_RCV_BUFF'):
                self.netflow_udp_rcv_buff = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_SFLOW_UDP_WORKERS'):
                self.sflow_udp_workers = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_SFLOW_UDP_QUEUE_SIZE'):
                self.sflow_udp_queue_size = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_SFLOW_UDP_RCV_BUFF'):
                self.sflow_udp_rcv_buff = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_UDP_WORKERS'):
                self.ipfix_udp_workers = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_UDP_QUEUE_SIZE'):
                self.ipfix_udp_queue_size = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_IPFIX_UDP_RCV_BUFF'):
                self.ipfix_udp_rcv_buff = line.split('=')[1].strip()
            elif line.startswith('ELASTIFLOW_ES_HOST'):
                self.es_host = line.split('=')[1].strip()

    def write_environment_variables(self):
        """
        Update the environment variables tied to ElastiFlow Logstash configurations
        """
        elastiflow_vars_map = {}
        new_env_content = ''
        lines = open('/etc/dynamite/environment').readlines()
        for var in vars(self):
            elastiflow_key = 'ELASTIFLOW_' + str(var).upper()
            elastiflow_vars_map[elastiflow_key] = getattr(self, var)
        for line in lines:
            if '=' in line:
                env_key = line.split('=')[0]
                if env_key in elastiflow_vars_map.keys():
                    line = '{}={}'.format(env_key, elastiflow_vars_map[env_key])
                    elastiflow_vars_map.pop(env_key, None)
            if line.strip() != '':
                new_env_content += line + '\n'
        for unwritten_key, unwritten_val in elastiflow_vars_map.items():
            new_env_content += '{}={}\n'.format(unwritten_key, unwritten_val)
        with open('/etc/dynamite/environment', 'w') as f:
            f.write(new_env_content)


class ElastiFlowInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/elastiflow/)
        """

        self.install_directory = install_directory

    @staticmethod
    def download_elasticflow(stdout=False):
        """
        Download Elastiflow archive

        :param stdout: Print output to console
        """
        for url in open(const.ELASTIFLOW_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.ELASTIFLOW_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_elastiflow(stdout=False):
        """
        Extract ElastiFlow to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.ELASTIFLOW_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.ELASTIFLOW_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_logstash_elastiflow(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating elastiflow install|configuration directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        if stdout:
            sys.stdout.write('[+] Copying elastiflow configurations\n')
        utilities.copytree(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'zeek'),
                           self.install_directory)
        utilities.set_ownership_of_file(self.install_directory)
        if 'ELASTIFLOW_DICT_PATH' not in open('/etc/dynamite/environment').read():
            dict_path = os.path.join(self.install_directory, 'dictionaries')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow dictionary configuration path [{}]\n'.format(dict_path))
            subprocess.call('echo ELASTIFLOW_DICT_PATH="{}" >> /etc/dynamite/environment'.format(dict_path), shell=True)
        if 'ELASTIFLOW_TEMPLATE_PATH' not in open('/etc/dynamite/environment').read():
            template_path = os.path.join(self.install_directory, 'templates')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow template configuration path [{}]\n'.format(template_path))
            subprocess.call('echo ELASTIFLOW_TEMPLATE_PATH="{}" >> /etc/dynamite/environment'.format(template_path), shell=True)
        if 'ELASTIFLOW_GEOIP_DB_PATH' not in open('/etc/dynamite/environment').read():
            geo_path = os.path.join(self.install_directory, 'geoipdbs')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow geodb configuration path [{}]\n'.format(geo_path))
            subprocess.call('echo ELASTIFLOW_GEOIP_DB_PATH="{}" >> /etc/dynamite/environment'.format(geo_path), shell=True)
        if 'ELASTIFLOW_DEFINITION_PATH' not in open('/etc/dynamite/environment').read():
            def_path = os.path.join(self.install_directory, 'definitions')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow definitions configuration path [{}]\n'.format(def_path))
            subprocess.call('echo ELASTIFLOW_DEFINITION_PATH="{}" >> /etc/dynamite/environment'.format(def_path), shell=True)
        ElastiflowConfigurator().write_environment_variables()
