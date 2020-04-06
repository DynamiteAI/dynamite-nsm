import os
import shutil
import unittest

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import config
from dynamite_nsm.services.suricata.tests import data


def create_dummy_suricatayaml(sc_config_directory):
    example_config_string = data.SURICATA_CONFIG

    with open(os.path.join(sc_config_directory, 'suricata.yaml'), 'w') as f:
        f.write(example_config_string)


class Tests(unittest.TestCase):

    def setUp(self):
        self.config_root = '/etc/dynamite/test'
        self.config_directory = os.path.join(self.config_root, 'suricata')

        # Setup Test Space
        utilities.makedirs(self.config_directory, exist_ok=True)
        create_dummy_suricatayaml(self.config_directory)

        self.config_manager = config.ConfigManager(configuration_directory=self.config_directory)

    def test_suricatayaml_add_af_packet_interfaces(self):
        self.config_manager.add_afpacket_interface(interface='mon0',
                                                   threads=5,
                                                   cluster_id=99,
                                                   cluster_type='cluster_flow')
        self.config_manager.write_config()

        config_manager_read = config.ConfigManager(configuration_directory=self.config_directory)

        assert ('mon0' in [interface['interface'] for interface in config_manager_read.af_packet_interfaces])

    def tearDown(self):
        shutil.rmtree(self.config_root, ignore_errors=True)
