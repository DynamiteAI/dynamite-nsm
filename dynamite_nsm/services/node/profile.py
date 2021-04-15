import os

from dynamite_nsm import const
from dynamite_nsm import utilities

from dynamite_nsm.services.base import profile
from dynamite_nsm.services.logstash import process as logstash_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.node_name = self.env_dict.get('NODE_NAME')

        profile.BaseProcessProfiler.__init__(self,
                                             install_directory='/home/dynamite-remote/.ssh/',
                                             config_directory='/home/dynamite-remote/.ssh/',
                                             required_install_files=[self.node_name],
                                             required_config_files=[self.node_name],
                                             )
