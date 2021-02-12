import unittest

from dynamite_nsm.service_objects.zeek.node import Workers
from dynamite_nsm.services.zeek.config import NodeConfigManager

ZEEK_INSTALL_DIRECTORY = '/opt/dynamite/zeek/'
CAPTURE_NETWORK_INTERFACES = ['eth0', 'eth1']


class Tests(unittest.TestCase):

    def setUp(self):
        self.node_config_manager = NodeConfigManager(ZEEK_INSTALL_DIRECTORY)

    def test_optimal_worker_configurations_unspecified_cpus(self):
        self.node_config_manager.workers = Workers()

        optimal_workers = self.node_config_manager.get_optimal_zeek_worker_config(
            interface_names=CAPTURE_NETWORK_INTERFACES, cpus=None)
        assert len(optimal_workers.get_raw()) == len(CAPTURE_NETWORK_INTERFACES)

    def test_optimal_worker_configurations_4_cpus(self):
        self.node_config_manager.workers = Workers()

        optimal_workers = self.node_config_manager.get_optimal_zeek_worker_config(
            interface_names=CAPTURE_NETWORK_INTERFACES,
            cpus=(0, 1, 2, 3))
        assert len(optimal_workers.get_raw()) == len(CAPTURE_NETWORK_INTERFACES)
