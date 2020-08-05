import os

from dynamite_nsm import const
from dynamite_nsm import utilities

from dynamite_nsm.services.base import profile
from dynamite_nsm.services.managerd import process as managerd_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.managerd_install = self.env_dict.get('MANAGERD_INSTALL')
        self.managerd_config = self.env_dict.get('MANAGERD_CONFIG')
        self.managerd_logs = self.env_dict.get('MANAGERD_LOGS')

        profile.BaseProcessProfiler.__init__(self,
                                             install_archive_path=os.path.join(const.INSTALL_CACHE,
                                                                               const.LOGSTASH_ARCHIVE_NAME),
                                             install_directory=self.managerd_install,
                                             config_directory=self.managerd_config,
                                             required_install_files=['managerd'],
                                             required_config_files=['config.yml']
                                             )

    def is_running(self):
        if self.managerd_install:
            try:
                return managerd_process.ProcessManager().status()['running']
            except KeyError:
                return managerd_process.ProcessManager().status()['RUNNING']
        return False
