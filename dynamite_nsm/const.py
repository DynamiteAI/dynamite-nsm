import os
try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser


DEFAULT_CONFIGS_URL = 'https://dynamite-config-staging.s3-us-west-2.amazonaws.com/dynamite-public/0.71/' \
                      'default_configs.tar.gz'
MIRRORS_CONFIG_URL = 'https://dynamite-config-staging.s3-us-west-2.amazonaws.com/dynamite-public/0.71/mirrors.tar.gz'
DEFAULT_CONFIGS_ARCHIVE_NAME = 'default_configs.tar.gz'
MIRRORS_CONFIG_ARCHIVE_NAME = 'mirrors.tar.gz'
DEFAULT_CONFIGS = "/etc/dynamite/default_configs/"
MIRRORS = "/etc/dynamite/mirrors/"
CONFIG_PATH = "/etc/dynamite"
LOG_PATH = '/var/log/dynamite/'
INSTALL_CACHE = "/tmp/dynamite/install_cache/"


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

VERSION = extracted_constants.get('VERSION')
DYNAMITE_SDK_ARCHIVE_NAME = extracted_constants.get('DYNAMITE_SDK_ARCHIVE_NAME')
ELASTIFLOW_ARCHIVE_NAME = extracted_constants.get('ELASTIFLOW_ARCHIVE_NAME')
ELASTICSEARCH_ARCHIVE_NAME = extracted_constants.get('ELASTICSEARCH_ARCHIVE_NAME')
LOGSTASH_ARCHIVE_NAME = extracted_constants.get('LOGSTASH_ARCHIVE_NAME')
FILE_BEAT_ARCHIVE_NAME = extracted_constants.get('FILE_BEAT_ARCHIVE_NAME')
JAVA_ARCHIVE_NAME = extracted_constants.get('JAVA_ARCHIVE_NAME')
KIBANA_ARCHIVE_NAME = extracted_constants.get('KIBANA_ARCHIVE_NAME')
OINKMASTER_ARCHIVE_NAME = extracted_constants.get('OINKMASTER_ARCHIVE_NAME')
PF_RING_ARCHIVE_NAME = extracted_constants.get('PF_RING_ARCHIVE_NAME')
SYNESIS_ARCHIVE_NAME = extracted_constants.get('SYNESIS_ARCHIVE_NAME')
SURICATA_ARCHIVE_NAME = extracted_constants.get('SURICATA_ARCHIVE_NAME')
ZEEK_ARCHIVE_NAME = extracted_constants.get('ZEEK_ARCHIVE_NAME')

DYNAMITE_SDK_DIRECTORY_NAME = extracted_constants.get('DYNAMITE_SDK_DIRECTORY_NAME')
ELASTIFLOW_DIRECTORY_NAME = extracted_constants.get('ELASTIFLOW_DIRECTORY_NAME')
ELASTICSEARCH_DIRECTORY_NAME = extracted_constants.get('ELASTICSEARCH_DIRECTORY_NAME')
FILE_BEAT_DIRECTORY_NAME = extracted_constants.get('FILE_BEAT_DIRECTORY_NAME')
JAVA_DIRECTORY_NAME = extracted_constants.get('JAVA_DIRECTORY_NAME')
KIBANA_DIRECTORY_NAME = extracted_constants.get('KIBANA_DIRECTORY_NAME')
LOGSTASH_DIRECTORY_NAME = extracted_constants.get('LOGSTASH_DIRECTORY_NAME')
OINKMASTER_DIRECTORY_NAME = extracted_constants.get('OINKMASTER_DIRECTORY_NAME')
PF_RING_DIRECTORY_NAME = extracted_constants.get('PF_RING_DIRECTORY_NAME')
SYNESIS_DIRECTORY_NAME = extracted_constants.get('SYNESIS_DIRECTORY_NAME')
SURICATA_DIRECTORY_NAME = extracted_constants.get('SURICATA_DIRECTORY_NAME')
ZEEK_DIRECTORY_NAME = extracted_constants.get('ZEEK_DIRECTORY_NAME')

DYNAMITE_SDK_MIRRORS = extracted_constants.get('DYNAMITE_SDK_MIRRORS')
ELASTIFLOW_MIRRORS = extracted_constants.get('ELASTIFLOW_MIRRORS')
ELASTICSEARCH_MIRRORS = extracted_constants.get('ELASTICSEARCH_MIRRORS')
FILE_BEAT_MIRRORS = extracted_constants.get('FILE_BEAT_MIRRORS')
LOGSTASH_MIRRORS = extracted_constants.get('LOGSTASH_MIRRORS')
KIBANA_MIRRORS = extracted_constants.get('KIBANA_MIRRORS')
JAVA_MIRRORS = extracted_constants.get('JAVA_MIRRORS')
OINKMASTER_MIRRORS = extracted_constants.get('OINKMASTER_MIRRORS')
PF_RING_MIRRORS = extracted_constants.get('PF_RING_MIRRORS')
SURICATA_MIRRORS = extracted_constants.get('SURICATA_MIRRORS')
SYNESIS_MIRRORS = extracted_constants.get('SYNESIS_MIRRORS')
ZEEK_MIRRORS = extracted_constants.get('ZEEK_MIRRORS')
