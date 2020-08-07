import os

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import profile
from dynamite_nsm.services.zeek import process as zeek_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        self.env_dict = utilities.get_environment_file_dict()
        self.zeek_home = self.env_dict.get('ZEEK_HOME')
        self.zeek_scripts = self.env_dict.get('ZEEK_SCRIPTS')

        profile.BaseProcessProfiler.__init__(self,
                                             install_archive_path=os.path.join(const.INSTALL_CACHE,
                                                                               const.ZEEK_ARCHIVE_NAME),
                                             install_directory=self.zeek_home,
                                             config_directory=self.zeek_scripts,
                                             required_install_files=['bin', 'etc', 'lib'],
                                             required_config_files=['site'])

    def is_running(self):
        if self.zeek_home:
            try:
                return zeek_process.ProcessManager().status()['running']
            except KeyError:
                return zeek_process.ProcessManager().status()['RUNNING']
        return False
