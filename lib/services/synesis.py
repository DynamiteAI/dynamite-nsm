import os
import sys
import tarfile
import subprocess

from lib import const
from lib import utilities

CONFIGURATION_DIRECTORY = '/etc/dynamite/logstash/synlite_suricata/conf.d/'
INSTALL_DIRECTORY = '/etc/dynamite/logstash/synlite_suricata/'


class SynesisConfigurator:
    """
    A configuration interface for SynesisLite (Suricata)
    """

    def __init__(self):
        self.suricata_resolve_ip2host = True
        self.suricata_nameserver = '127.0.0.1'
        self.suricata_dns_hit_cache_size = 25000
        self.suricata_dns_hit_cache_ttl = 900
        self.suricata_dns_failed_cache_size = 75000
        self.suricata_dns_failed_cache_ttl = 3600

        self.suricata_es_host = '127.0.0.1'

        self.suricata_beats_host = '0.0.0.0'
        self.suricata_beats_port = 5044

    def _parse_environment_file(self):
        for line in open('/etc/environment').readlines():
            if line.startswith('SYNLITE_SURICATA_RESOLVE_IP2HOST'):
                self.suricata_resolve_ip2host = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_NAMESERVER'):
                self.suricata_nameserver = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_DNS_HIT_CACHE_SIZE'):
                self.suricata_dns_hit_cache_size = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_DNS_HIT_CACHE_TTL'):
                self.suricata_dns_hit_cache_ttl = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_DNS_FAILED_CACHE_SIZE'):
                self.suricata_dns_failed_cache_size = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_DNS_FAILED_CACHE_TTL'):
                self.suricata_dns_failed_cache_ttl = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_ES_HOST'):
                self.suricata_es_host = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_BEATS_HOST'):
                self.suricata_beats_host = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_BEATS_PORT'):
                self.suricata_beats_port = line.split('=')[1].strip()

    def write_environment_variables(self):
        """
        Update the environment variables tied to SynesisLite Logstash configurations
        """
        synlite_vars_map = {}
        new_env_content = ''
        lines = open('/etc/environment').readlines()
        for var in vars(self):
            synlite_key = 'SYNLITE_' + str(var).upper()
            synlite_vars_map[synlite_key] = getattr(self, var)
        for line in lines:
            if '=' in line:
                env_key = line.split('=')[0]
                if env_key in synlite_vars_map.keys():
                    line = '{}={}'.format(env_key, synlite_vars_map[env_key])
                    synlite_vars_map.pop(env_key, None)
            if line.strip() != '':
                new_env_content += line + '\n'
        for unwritten_key, unwritten_val in synlite_vars_map.items():
            new_env_content += '{}={}\n'.format(unwritten_key, unwritten_val)
        with open('/etc/environment', 'w') as f:
            f.write(new_env_content)