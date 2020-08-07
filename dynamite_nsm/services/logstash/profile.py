import os

from dynamite_nsm import const
from dynamite_nsm import utilities

from dynamite_nsm.services.base import profile
from dynamite_nsm.services.logstash import process as logstash_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        self.env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.env_dict = utilities.get_environment_file_dict()
        self.logstash_home = self.env_dict.get('LS_HOME')
        self.logstash_config = self.env_dict.get('LS_PATH_CONF')

        profile.BaseProcessProfiler.__init__(self,
                                             install_archive_path=os.path.join(const.INSTALL_CACHE,
                                                                               const.LOGSTASH_ARCHIVE_NAME),
                                             install_directory=self.logstash_home,
                                             config_directory=self.logstash_config,
                                             required_install_files=['bin', 'data', 'lib', 'logstash-core'],
                                             required_config_files=['logstash.yml', 'jvm.options']
                                             )

    def is_running(self):
        if self.logstash_home:
            try:
                return logstash_process.ProcessManager().status()['running']
            except KeyError:
                return logstash_process.ProcessManager().status()['RUNNING']
        return False
