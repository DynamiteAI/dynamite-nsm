import os

from dynamite_nsm import const
from dynamite_nsm.services.logstash.elastiflow import exceptions as elastiflow_exceptions


class ConfigManager:
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
        try:
            with open(os.path.join(const.CONFIG_PATH, 'environment')) as env_f:
                for line in env_f.readlines():
                    if line.startswith('ES_PASSWD'):
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
        except Exception as e:
            raise elastiflow_exceptions.ReadElastiflowConfigError(
                "General error occurred while reading elastiflow environment variables: {}".format(e))

    def write_environment_variables(self):
        """
        Update the environment variables tied to ElastiFlow Logstash configurations
        """
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        elastiflow_vars_map = {}
        new_env_content = ''
        lines = open(env_file).readlines()
        for var in vars(self):
            if str(var).upper() == 'ES_PASSWD':
                elastiflow_key = str(var).upper()
            else:
                elastiflow_key = 'ELASTIFLOW_' + str(var).upper()
            elastiflow_vars_map[elastiflow_key] = getattr(self, var)
        for line in lines:
            if '=' in line:
                env_key = line.split('=')[0]
                if env_key in elastiflow_vars_map.keys():
                    line = '{}={}'.format(env_key, elastiflow_vars_map[env_key])
                    elastiflow_vars_map.pop(env_key, None)
            if line.strip() != '':
                new_env_content += line.strip() + '\n'
        for unwritten_key, unwritten_val in elastiflow_vars_map.items():
            new_env_content += '{}={}\n'.format(unwritten_key, unwritten_val)
        try:
            with open(env_file, 'w') as f:
                f.write(new_env_content)
        except IOError:
            raise elastiflow_exceptions.WriteElastiflowConfigError(
                "Could not locate {}".format(const.CONFIG_PATH))
        except Exception as e:
            raise elastiflow_exceptions.WriteElastiflowConfigError(
                "General error while attempting to write new elastiflow environment variables; {}".format(e))
