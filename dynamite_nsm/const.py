import os
try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser


DEFAULT_CONFIGS_URL = 'https://dynamite-config-staging.s3-us-west-2.amazonaws.com/dynamite-dev/0.72/' \
                      'default_configs.tar.gz'
MIRRORS_CONFIG_URL = 'https://dynamite-config-staging.s3-us-west-2.amazonaws.com/dynamite-dev/0.72/mirrors.tar.gz'
DEFAULT_CONFIGS_ARCHIVE_NAME = 'default_configs.tar.gz'
MIRRORS_CONFIG_ARCHIVE_NAME = 'mirrors.tar.gz'
DEFAULT_CONFIGS = "/etc/dynamite/default_configs/"
MIRRORS = "/etc/dynamite/mirrors/"
INSTALL_PATH = "/opt/dynamite"
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

VERSION = extracted_constants.get('VERSION', '0.7.2')
DYNAMITE_SDK_ARCHIVE_NAME = extracted_constants.get('DYNAMITE_SDK_ARCHIVE_NAME', 'dynamite-sdk-lite-0.1.2.tar.gz')
ELASTIFLOW_ARCHIVE_NAME = extracted_constants.get('ELASTIFLOW_ARCHIVE_NAME', 'elastiflow-vlabs-0.5.3-3.5.0.tar.gz')
ELASTICSEARCH_ARCHIVE_NAME = extracted_constants.get('ELASTICSEARCH_ARCHIVE_NAME', 'elasticsearch-7.2.0.tar.gz')
LOGSTASH_ARCHIVE_NAME = extracted_constants.get('LOGSTASH_ARCHIVE_NAME', 'logstash-7.2.0.tar.gz')
FILE_BEAT_ARCHIVE_NAME = extracted_constants.get('FILE_BEAT_ARCHIVE_NAME', 'filebeat-7.2.0-linux-x86_64.tar.gz')
JAVA_ARCHIVE_NAME = extracted_constants.get('JAVA_ARCHIVE_NAME', 'java-11.0.2.tar.gz')
KIBANA_ARCHIVE_NAME = extracted_constants.get('KIBANA_ARCHIVE_NAME', 'kibana-7.2.1-linux-x86_64.tar.gz')
OINKMASTER_ARCHIVE_NAME = extracted_constants.get('OINKMASTER_ARCHIVE_NAME', 'oinkmaster-snapshot.tar.gz')
PF_RING_ARCHIVE_NAME = extracted_constants.get('PF_RING_ARCHIVE_NAME', 'PF_RING-7.4.0.tar.gz')
SYNESIS_ARCHIVE_NAME = extracted_constants.get('SYNESIS_ARCHIVE_NAME', 'synesis_lite_suricata-vlabs-0.1.0-1.1.0.tar.gz')
SURICATA_ARCHIVE_NAME = extracted_constants.get('SURICATA_ARCHIVE_NAME', 'suricata-4.1.8.tar.gz')
ZEEK_ARCHIVE_NAME = extracted_constants.get('ZEEK_ARCHIVE_NAME', 'zeek-3.0.3.tar.gz')
DYNAMITED_ARCHIVE_NAME = extracted_constants.get('DYNAMITED_ARCHIVE_NAME', 'dynamited-0.1.0.tar.gz')
DYNAMITE_SDK_DIRECTORY_NAME = extracted_constants.get('DYNAMITE_SDK_DIRECTORY_NAME', 'dynamite-sdk-lite-0.1.2')
ELASTIFLOW_DIRECTORY_NAME = extracted_constants.get('ELASTIFLOW_DIRECTORY_NAME', 'elastiflow-vlabs-0.5.3-3.5.0')
ELASTICSEARCH_DIRECTORY_NAME = extracted_constants.get('ELASTICSEARCH_DIRECTORY_NAME', 'elasticsearch-7.2.0')
FILE_BEAT_DIRECTORY_NAME = extracted_constants.get('FILE_BEAT_DIRECTORY_NAME', 'filebeat-7.2.0-linux-x86_64')
JAVA_DIRECTORY_NAME = extracted_constants.get('JAVA_DIRECTORY_NAME', 'java-11.0.2')
KIBANA_DIRECTORY_NAME = extracted_constants.get('KIBANA_DIRECTORY_NAME', 'kibana-7.2.1-linux-x86_64')
LOGSTASH_DIRECTORY_NAME = extracted_constants.get('LOGSTASH_DIRECTORY_NAME', 'logstash-7.2.0')
OINKMASTER_DIRECTORY_NAME = extracted_constants.get('OINKMASTER_DIRECTORY_NAME', 'oinkmaster')
PF_RING_DIRECTORY_NAME = extracted_constants.get('PF_RING_DIRECTORY_NAME', 'PF_RING-7.4.0')
SYNESIS_DIRECTORY_NAME = extracted_constants.get('SYNESIS_DIRECTORY_NAME', 'synesis_lite_suricata-vlabs-0.1.0-1.1.0')
SURICATA_DIRECTORY_NAME = extracted_constants.get('SURICATA_DIRECTORY_NAME', 'suricata-4.1.8')
ZEEK_DIRECTORY_NAME = extracted_constants.get('ZEEK_DIRECTORY_NAME', 'zeek-3.0.3')

DYNAMITE_SDK_MIRRORS = extracted_constants.get('DYNAMITE_SDK_MIRRORS', '/etc/dynamite/mirrors/dynamite_sdk')
ELASTIFLOW_MIRRORS = extracted_constants.get('ELASTIFLOW_MIRRORS', '/etc/dynamite/mirrors/elastiflow')
ELASTICSEARCH_MIRRORS = extracted_constants.get('ELASTICSEARCH_MIRRORS', '/etc/dynamite/mirrors/elasticsearch')
FILE_BEAT_MIRRORS = extracted_constants.get('FILE_BEAT_MIRRORS', '/etc/dynamite/mirrors/filebeat')
LOGSTASH_MIRRORS = extracted_constants.get('LOGSTASH_MIRRORS', '/etc/dynamite/mirrors/logstash')
KIBANA_MIRRORS = extracted_constants.get('KIBANA_MIRRORS', '/etc/dynamite/mirrors/kibana')
JAVA_MIRRORS = extracted_constants.get('JAVA_MIRRORS', '/etc/dynamite/mirrors/java')
OINKMASTER_MIRRORS = extracted_constants.get('OINKMASTER_MIRRORS', '/etc/dynamite/mirrors/oinkmaster_nightly')
PF_RING_MIRRORS = extracted_constants.get('PF_RING_MIRRORS', '/etc/dynamite/mirrors/pf_ring')
SURICATA_MIRRORS = extracted_constants.get('SURICATA_MIRRORS', '/etc/dynamite/mirrors/pf_ring')
SYNESIS_MIRRORS = extracted_constants.get('SYNESIS_MIRRORS', '/etc/dynamite/mirrors/pf_ring')
ZEEK_MIRRORS = extracted_constants.get('ZEEK_MIRRORS', '/etc/dynamite/mirrors/zeek')
DYNAMITED_MIRRORS = extracted_constants.get('DYNAMITED_MIRRORS', '/etc/dynamite/mirrors/dynamited')

