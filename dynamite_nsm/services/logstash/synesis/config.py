import os

from dynamite_nsm import const


class ConfigManager:
    """
    A configuration interface for SynesisLite (Suricata)
    """

    def __init__(self):
        self.es_passwd = 'changeme'
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
        for line in open(os.path.join(const.CONFIG_PATH, 'environment')).readlines():
            if line.startswith('ES_PASSWD'):
                self.es_passwd = line.split('=')[1].strip()
            elif line.startswith('SYNLITE_SURICATA_RESOLVE_IP2HOST'):
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
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        synlite_vars_map = {}
        new_env_content = ''
        lines = open(env_file).readlines()
        for var in vars(self):
            if str(var).upper() == 'ES_PASSWD':
                synlite_key = str(var).upper()
            else:
                synlite_key = 'SYNLITE_' + str(var).upper()
            synlite_vars_map[synlite_key] = getattr(self, var)
        for line in lines:
            if '=' in line:
                env_key = line.split('=')[0]
                if env_key in synlite_vars_map.keys():
                    line = '{}={}'.format(env_key, synlite_vars_map[env_key])
                    synlite_vars_map.pop(env_key, None)
            if line.strip() != '':
                new_env_content += line.strip() + '\n'
        for unwritten_key, unwritten_val in synlite_vars_map.items():
            new_env_content += '{}={}\n'.format(unwritten_key, unwritten_val)
        with open(env_file, 'w') as f:
            f.write(new_env_content)
