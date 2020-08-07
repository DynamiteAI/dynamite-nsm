import os

from dynamite_nsm import const
from dynamite_nsm import utilities

from dynamite_nsm.services.base import profile
from dynamite_nsm.services.elasticsearch import config as elastic_configs
from dynamite_nsm.services.elasticsearch import process as elastic_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.elasticsearch_home = self.env_dict.get('ES_HOME')
        self.elasticsearch_config = self.env_dict.get('ES_PATH_CONF')

        profile.BaseProcessProfiler.__init__(self,
                                             install_archive_path=os.path.join(const.INSTALL_CACHE,
                                                                               const.ELASTICSEARCH_ARCHIVE_NAME),
                                             install_directory=self.elasticsearch_home,
                                             config_directory=self.elasticsearch_config,
                                             required_install_files=['bin', 'data', 'lib', 'modules'],
                                             required_config_files=['elasticsearch.yml', 'jvm.options']
                                             )

    def is_running(self):
        if self.elasticsearch_home:
            try:
                return elastic_process.ProcessManager().status()['running']
            except KeyError:
                return elastic_process.ProcessManager().status()['RUNNING']
        return False

    def is_listening(self):
        if not self.elasticsearch_config:
            return False
        if not os.path.exists(self.elasticsearch_config):
            return False

        es_config_obj = elastic_configs.ConfigManager(configuration_directory=self.elasticsearch_config)
        host = es_config_obj.network_host
        port = es_config_obj.http_port
        if host.strip() == '0.0.0.0':
            host = 'localhost'
        return utilities.check_socket(host, port)
