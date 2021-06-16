import os
try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser


DEFAULT_CONFIGURATIONS_URL = 'https://github.com/DynamiteAI/configurations/archive/refs/tags/1.0.tar.gz'
CONFIG_DELTA_CHANGE_SET = None  # We'll support these later

EMERGING_THREATS_OPEN = 'http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz'
DEFAULT_CONFIGS = "/etc/dynamite/default_configs/"
MIRRORS = "/etc/dynamite/mirrors/"
INSTALL_PATH = "/opt/dynamite"
CONFIG_PATH = "/etc/dynamite"
LOG_PATH = '/var/log/dynamite/'
PID_PATH = '/var/run/dynamite/'
STATE_PATH = '/var/dynamite/'
JVM_ROOT = '/usr/lib/jvm/'
SYS_BIN = '/usr/bin/'
INSTALL_CACHE = "/tmp/dynamite/install_cache/"
PCAP_PATH = "/etc/dynamite/pcaps/"


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

VERSION = extracted_constants.get('VERSION', '1.0.0')
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

