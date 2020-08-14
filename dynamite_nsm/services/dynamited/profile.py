import os

from dynamite_nsm import const
from dynamite_nsm import utilities

from dynamite_nsm.services.base import profile
from dynamite_nsm.services.dynamited import process as dynamited_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.dynamited_install = self.env_dict.get('DYNAMITED_INSTALL')
        self.dynamited_config = self.env_dict.get('DYNAMITED_CONFIG')
        self.dynamited_logs = self.env_dict.get('DYNAMITED_LOGS')

        profile.BaseProcessProfiler.__init__(self,
                                             install_archive_path=os.path.join(const.INSTALL_CACHE,
                                                                               const.DYNAMITED_ARCHIVE_NAME),
                                             install_directory=self.dynamited_install,
                                             config_directory=self.dynamited_config,
                                             required_install_files=['bin'],
                                             required_config_files=['config.yml']
                                             )

    def is_running(self):
        if self.dynamited_install:
            try:
                return dynamited_process.ProcessManager().status()['running']
            except KeyError:
                return dynamited_process.ProcessManager().status()['RUNNING']
        return False
