import os

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import profile
from dynamite_nsm.services.filebeat import process as filebeat_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.filebeat_home = self.env_dict.get('FILEBEAT_HOME')

        profile.BaseProcessProfiler.__init__(self,
                                             install_archive_path=os.path.join(const.INSTALL_CACHE,
                                                                               const.FILE_BEAT_ARCHIVE_NAME),
                                             install_directory=self.filebeat_home,
                                             config_directory=self.filebeat_home,
                                             required_install_files=['filebeat', 'filebeat.yml']
                                             )

    def is_running(self) -> bool:
        if self.filebeat_home:
            try:
                return filebeat_process.ProcessManager().status()['running']
            except KeyError:
                return filebeat_process.ProcessManager().status()['RUNNING']
        return False
