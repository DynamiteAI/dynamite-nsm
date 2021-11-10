import os
import shutil
import unittest

from dynamite_nsm.services.suricata.config import ConfigManager
from dynamite_nsm.utilities import get_environment_file_dict, makedirs


class TestSuricataConfigManager(unittest.TestCase):
    """
    Test Zeek node.cfg after a vanilla installation of the Zeek component
    """

    def setUp(self) -> None:
        env_file = get_environment_file_dict()
        self.suricata_home = env_file.get('SURICATA_HOME')
        self.suricata_config = env_file.get('SURICATA_CONFIG')
        self.test_config_directory = '/tmp/dynamite/suricata_test_configs/'
        makedirs(self.test_config_directory)

    def tearDown(self) -> None:
        shutil.rmtree(self.test_config_directory)

    def test_suricata_home_directory_exists(self):
        assert self.suricata_home and os.path.exists(self.suricata_home)

    def test_suricata_config_directory_exists(self):
        assert self.suricata_config and os.path.exists(self.suricata_config)

    def test_suricata_config_parsable(self):
        assert ConfigManager(self.suricata_config).runmode == 'autofp'

    def test_suricata_update_home_net_and_commit(self):
        conf = ConfigManager(self.suricata_config)
        conf.home_net = ["192.168.0.5-255"]
        conf.commit(out_file_path=f'{self.test_config_directory}/suricata.yaml')

        read_conf = ConfigManager(self.test_config_directory)
        assert read_conf.home_net[0] == "192.168.0.5-255"

