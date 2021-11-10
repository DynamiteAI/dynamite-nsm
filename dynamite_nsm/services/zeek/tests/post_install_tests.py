import os
import shutil
import unittest

from dynamite_nsm.services.base.config_objects.zeek.node import Logger, Proxy, Worker, Workers
from dynamite_nsm.services.zeek.config import NodeConfigManager
from dynamite_nsm.utilities import get_environment_file_dict, makedirs

CAPTURE_NETWORK_INTERFACES = ['eth0', 'eth1']


class TestZeekNodeConfigManager(unittest.TestCase):
    """
    Test Zeek node.cfg after a vanilla installation of the Zeek component
    """

    def setUp(self) -> None:
        env_file = get_environment_file_dict()
        self.zeek_home = env_file.get('ZEEK_HOME')
        self.zeek_scripts = env_file.get('ZEEK_SCRIPTS')
        self.test_config_directory = '/tmp/dynamite/zeek_test_configs/'
        makedirs(f'{self.test_config_directory}/etc/')

    def tearDown(self) -> None:
        shutil.rmtree(self.test_config_directory)

    def test_zeek_home_directory_exists(self):
        assert self.zeek_home and os.path.exists(self.zeek_home)

    def test_zeek_scripts_directory_exists(self):
        assert self.zeek_scripts and os.path.exists(self.zeek_scripts)

    def test_zeek_node_config_parsable(self):
        assert NodeConfigManager(self.zeek_home).install_directory == self.zeek_home

    def test_zeek_node_manager_exists(self):
        assert NodeConfigManager(self.zeek_home).manager.type == 'manager'

    def test_zeek_node_loggers_exist(self):
        assert NodeConfigManager(self.zeek_home).loggers.items[0].name == 'dynamite-logger'

    def test_zeek_node_proxies_exist(self):
        assert NodeConfigManager(self.zeek_home).proxies.items[0].name == 'dynamite-proxy-1'

    def test_zeek_node_atleast_one_worker(self):
        assert (len(NodeConfigManager(self.zeek_home).workers.items)) > 0

    def test_zeek_node_config_optimal_worker_configurations_unspecified_cpus(self):
        NodeConfigManager(self.zeek_home).workers = Workers()

        optimal_workers = NodeConfigManager(self.zeek_home).get_optimal_zeek_worker_config(
            interface_names=CAPTURE_NETWORK_INTERFACES, available_cpus=None)
        assert len(optimal_workers.get_raw()) == len(CAPTURE_NETWORK_INTERFACES)

    def test_zeek_node_config_optimal_worker_configurations_4_cpus(self):
        NodeConfigManager.workers = Workers()
        optimal_workers = NodeConfigManager(self.zeek_home).get_optimal_zeek_worker_config(
            interface_names=CAPTURE_NETWORK_INTERFACES,
            available_cpus=(0, 1, 2, 3))
        assert len(optimal_workers.get_raw()) == len(CAPTURE_NETWORK_INTERFACES)

    def test_zeek_node_add_logger_and_commit(self):
        node_config_manager = NodeConfigManager(self.zeek_home)
        node_config_manager.loggers.add_logger(
            Logger(logger_name='dummy-logger', host='localhost')
        )
        node_config_manager.commit(out_file_path=f'{self.test_config_directory}/etc/node.cfg')
        assert (NodeConfigManager(self.test_config_directory).loggers.items[-1].name == 'dummy-logger')

    def test_zeek_node_add_proxy_and_commit(self):
        node_config_manager = NodeConfigManager(self.zeek_home)
        node_config_manager.proxies.add_proxy(
            Proxy(proxy_name='dummy-proxy', host='localhost')
        )
        node_config_manager.commit(out_file_path=f'{self.test_config_directory}/etc/node.cfg')
        assert (NodeConfigManager(self.test_config_directory).proxies.items[-1].name == 'dummy-proxy')

    def test_zeek_node_add_worker_and_commit(self):
        node_config_manager = NodeConfigManager(self.zeek_home)
        node_config_manager.workers.add_worker(
            Worker(
                worker_name='dummy-worker',
                interface_name='eth0',
                cluster_id=9001,
                cluster_type='FANOUT_HASH',
                pinned_cpus=(0, 1, 2),
                load_balance_processes=3,
                host='192.168.0.5'
            )
        )
        node_config_manager.commit(out_file_path=f'{self.test_config_directory}/etc/node.cfg')
        read_node_config_manager = NodeConfigManager(self.test_config_directory)
        dummy_worker = read_node_config_manager.workers['dummy-worker']
        assert (
            dummy_worker.name == 'dummy-worker' and
            dummy_worker.interface == 'eth0' and
            dummy_worker.cluster_id == 9001 and
            dummy_worker.cluster_type == "FANOUT_HASH" and
            dummy_worker.load_balance_processes == 3 and
            dummy_worker.pinned_cpus == [0, 1, 2] and
            dummy_worker.host == "192.168.0.5"

        )

    def test_zeek_node_remove_logger_and_commit(self):
        node_config_manager = NodeConfigManager(self.zeek_home)
        logger_name = node_config_manager.loggers.items[0].name
        node_config_manager.loggers.remove(logger_name)
        node_config_manager.commit(out_file_path=f'{self.test_config_directory}/etc/node.cfg')
        read_node_config_manager = NodeConfigManager(self.test_config_directory)
        removed = False
        try:
            read_node_config_manager.loggers[logger_name]
        except KeyError:
            removed = True
        assert removed

    def test_zeek_node_remove_worker_and_commit(self):
        node_config_manager = NodeConfigManager(self.zeek_home)
        worker_name = node_config_manager.workers.items[0].name
        node_config_manager.workers.remove(worker_name)
        node_config_manager.commit(out_file_path=f'{self.test_config_directory}/etc/node.cfg')
        read_node_config_manager = NodeConfigManager(self.test_config_directory)
        removed = False
        try:
            read_node_config_manager.workers[worker_name]
        except KeyError:
            removed = True
        assert removed
