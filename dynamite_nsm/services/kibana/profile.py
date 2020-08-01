import os

from dynamite_nsm import const
from dynamite_nsm import utilities

from dynamite_nsm.services.base import profile
from dynamite_nsm.services.kibana import config as kibana_config
from dynamite_nsm.services.kibana import process as kibana_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.kibana_home = self.env_dict.get('KIBANA_HOME')
        self.kibana_config = self.env_dict.get('KIBANA_PATH_CONF')

        profile.BaseProcessProfiler.__init__(self,
                                             install_archive_path=os.path.join(const.INSTALL_CACHE,
                                                                               const.KIBANA_ARCHIVE_NAME),
                                             install_directory=self.kibana_home,
                                             config_directory=self.kibana_config,
                                             required_install_files=['bin', 'data', 'node', 'optimize'],
                                             required_config_files=['kibana.yml']
                                             )

    def is_running(self):
        if self.kibana_home:
            try:
                return kibana_process.ProcessManager().status()['running']
            except KeyError:
                return kibana_process.ProcessManager().status()['RUNNING']
        return False

    def is_listening(self):
        if not self.kibana_config:
            return False
        if not os.path.exists(self.kibana_config):
            return False

        kb_config_obj = kibana_config.ConfigManager(configuration_directory=self.kibana_config)
        host = kb_config_obj.server_host
        port = kb_config_obj.server_port
        if host.strip() == '0.0.0.0':
            host = 'localhost'
        return utilities.check_socket(host, port)
