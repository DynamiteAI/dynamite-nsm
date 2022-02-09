import os
try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser


DEFAULT_CONFIGURATIONS_URL = 'https://github.com/DynamiteAI/configurations/archive/refs/tags/1.1.4.tar.gz'
CONFIG_DELTA_CHANGE_SET = None  # We'll support these later
ZEEK_PACKAGES = [
    'https://github.com/DynamiteAI/dynamite-community-id.git',
    'https://github.com/J-Gras/zeek-af_packet-plugin.git',
    'https://github.com/corelight/cve-2021-44228.git',
    'https://github.com/DynamiteAI/zeek-utils.git',
]

EMERGING_THREATS_OPEN = 'http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz'
CONFIG_PATH = "/etc/dynamite/"
DEFAULT_CONFIGS = f"{CONFIG_PATH}/default_configs/"
MIRRORS = "/etc/dynamite/mirrors/"
INSTALL_PATH = "/opt/dynamite"
LOG_PATH = '/var/log/dynamite/'
STATE_PATH = '/var/dynamite/'

INSTALL_CACHE = "/tmp/dynamite/install_cache/"
PCAP_PATH = "/etc/dynamite/pcaps/"

JVM_ROOT = '/usr/lib/jvm/'
PID_PATH = '/var/run/'
SYS_BIN = '/usr/bin/'
SSH_CONF_FILE = '/etc/ssh/ssh_config'
SSH_CONF_DIRECTORY = '/etc/ssh/ssh_config.d/'
SUDOERS_FILE = '/etc/sudoers'
SUDOERS_DIRECTORY = '/etc/sudoers.d/'


def bootstrap_constants_from_const_environment_file():
    constants = {}
    config_parser = ConfigParser()
    try:
        with open(os.path.join(DEFAULT_CONFIGS, '.constants')) as f:
            config_parser.readfp(f)
            for sect in config_parser.sections():
                for k, v in config_parser.items(sect):
                    constants[k.upper()] = v
    except Exception:
        pass
    return constants


extracted_constants = bootstrap_constants_from_const_environment_file()

VERSION = '1.1.4'
ELASTICSEARCH_MIRRORS = extracted_constants.get('ELASTICSEARCH_MIRRORS', '/etc/dynamite/mirrors/elasticsearch')
LOGSTASH_MIRRORS = extracted_constants.get('LOGSTASH_MIRRORS', '/etc/dynamite/mirrors/logstash')
KIBANA_MIRRORS = extracted_constants.get('KIBANA_MIRRORS', '/etc/dynamite/mirrors/kibana')
FILE_BEAT_MIRRORS = extracted_constants.get('FILE_BEAT_MIRRORS', '/etc/dynamite/mirrors/filebeat')
JAVA_MIRRORS = extracted_constants.get('JAVA_MIRRORS', '/etc/dynamite/mirrors/java')
OINKMASTER_MIRRORS = extracted_constants.get('OINKMASTER_MIRRORS', '/etc/dynamite/mirrors/oinkmaster_nightly')
SURICATA_MIRRORS = extracted_constants.get('SURICATA_MIRRORS', '/etc/dynamite/mirrors/suricata')
ZEEK_MIRRORS = extracted_constants.get('ZEEK_MIRRORS', '/etc/dynamite/mirrors/zeek')
DYNAMITED_MIRRORS = extracted_constants.get('DYNAMITED_MIRRORS', '/etc/dynamite/mirrors/dynamited')
CONFIG_BACKUP_PATH = extracted_constants.get('CONFIG_BACKUP_PATH', '/etc/dynamite/.backups')

