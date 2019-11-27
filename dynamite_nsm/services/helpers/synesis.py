import os
import sys
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities

INSTALL_DIRECTORY = '/etc/dynamite/logstash/synesis/'


class SynesisConfigurator:
    """
    A configuration interface for SynesisLite (Suricata)
    """

    def __init__(self):
        self.suricata_es_passwd = 'changeme'
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
        for line in open('/etc/dynamite/environment').readlines():
            if line.startswith('SYNLITE_SURICATA_ES_PASSWD'):
                self.suricata_es_passwd = line.split('=')[1].strip()
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
        synlite_vars_map = {}
        new_env_content = ''
        lines = open('/etc/dynamite/environment').readlines()
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
        with open('/etc/dynamite/environment', 'w') as f:
            f.write(new_env_content)


class SynesisInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        """
        :param install_directory: Path to the install directory (E.G /etc/dynamite/logstash/synlite_suricata/)
        """
        self.install_directory = install_directory

    @staticmethod
    def download_synesis(stdout=False):
        """
        Download SynesisLite (Suricata) archive

        :param stdout: Print output to console
        """
        for url in open(const.SYNESIS_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.SYNESIS_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_synesis(stdout=False):
        """
        Extract SynesisLite (Suricata) archive to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.SYNESIS_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.SYNESIS_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_logstash_synesis(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating synesis install|configuration directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        if stdout:
            sys.stdout.write('[+] Copying synesis configurations\n')
        utilities.copytree(os.path.join(const.DEFAULT_CONFIGS, 'logstash',
                                        'suricata'),
                           self.install_directory)
        utilities.set_ownership_of_file(self.install_directory)
        if 'SYNLITE_SURICATA_DICT_PATH' not in open('/etc/dynamite/environment').read():
            dict_path = os.path.join(self.install_directory, 'dictionaries')
            if stdout:
                sys.stdout.write('[+] Updating Synesis dictionary configuration path [{}]\n'.format(dict_path))
            subprocess.call('echo SYNLITE_SURICATA_DICT_PATH="{}" >> /etc/dynamite/environment'.format(dict_path), shell=True)
        if 'SYNLITE_SURICATA_TEMPLATE_PATH' not in open('/etc/dynamite/environment').read():
            template_path = os.path.join(self.install_directory, 'templates')
            if stdout:
                sys.stdout.write('[+] Updating Synesis template configuration path [{}]\n'.format(template_path))
            subprocess.call('echo SYNLITE_SURICATA_TEMPLATE_PATH="{}" >> /etc/dynamite/environment'.format(template_path), shell=True)
        if 'SYNLITE_SURICATA_GEOIP_DB_PATH' not in open('/etc/dynamite/environment').read():
            geo_path = os.path.join(self.install_directory, 'geoipdbs')
            if stdout:
                sys.stdout.write('[+] Updating Synesis geodb configuration path [{}]\n'.format(geo_path))
            subprocess.call('echo SYNLITE_SURICATA_GEOIP_DB_PATH="{}" >> /etc/dynamite/environment'.format(geo_path), shell=True)
        SynesisConfigurator().write_environment_variables()
