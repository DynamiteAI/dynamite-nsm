import json
from typing import Dict, List, Optional, Tuple

from dynamite_nsm.services.base.config_objects.generic import GenericItem, GenericItemGroup

CLUSTER_TYPE_TO_AF_PACKET_FANOUT_MODE_MAP = dict(
    cluster_flow='FANOUT_HASH',
    cluster_cpu='FANOUT_CPU',
    cluster_qm='FANOUT_QM'
)


class BaseComponent(GenericItem):

    def __init__(self, component_name: str, component_type: str, host: Optional[str] = 'localhost'):
        self.name = component_name
        self.type = component_type
        self.host = host

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                name=self.name,
                type=self.type,
                host=self.host
            )
        )

    def get_raw(self) -> Tuple[str, Dict]:
        return (self.name, dict(
            type=self.type,
            host=self.host
        ))


class BaseComponents(GenericItemGroup):

    def __init__(self, components: Optional[List[BaseComponent]] = None):
        super().__init__('name', components)
        self._idx = 0
        self.components = self.items

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                components=[component.name for component in self.components]
            )
        )

    def get_raw(self) -> List[Tuple[str, Dict]]:
        return [component.get_raw() for component in self.components]


class Logger(BaseComponent):

    def __init__(self, logger_name: str, host: str):
        """
        A Zeek logger process
        Args:
            logger_name: The name of the logger
            host: The host to bind to
        """
        super().__init__(logger_name, 'logger', host)


class Manager(BaseComponent):

    def __init__(self, manager_name: str, host: str):
        """
        A Zeek manager process
        Args:
            manager_name: The name of the logger
            host: The host to bind to
        """
        super().__init__(manager_name, 'manager', host)


class Proxy(BaseComponent):
    """
    A Zeek proxy process
    Args:
        proxy_name: The name of the logger
        host: The host to bind to
    """
    def __init__(self, proxy_name: str, host: str):
        super().__init__(proxy_name, 'proxy', host)


class Worker(BaseComponent):

    def __init__(self, worker_name: str, interface_name: str, cluster_id: int,
                 cluster_type: Optional[str] = 'FANOUT_HASH', load_balance_processes: Optional[int] = 1,
                 pinned_cpus: Optional[Tuple] = (0,), host: Optional[str] = 'localhost'):
        """A Zeek worker process that uses AF_PACKET for packet acquisition
        Args:
            worker_name: The name of the worker
            interface_name: The name of a network interface to monitor
            cluster_id: A unique integer associated with this worker. Maps to af_packet_fanout_id
            cluster_type: The algorithm used to spread traffic between sockets. Maps to af_packet_fanout_mode
            load_balance_processes: The number of Zeek processes associated with a given worker
            pinned_cpus: List of CPU cores that are dedicated to this worker
            host: The host to bind to
        Returns:
            None
        """
        super().__init__(worker_name, 'worker', host)

        self.name = worker_name
        self.interface = interface_name.replace('af_packet::', '')
        self.cluster_id = cluster_id
        self.cluster_type = cluster_type.replace('AF_Packet::', '')
        if self.cluster_type in CLUSTER_TYPE_TO_AF_PACKET_FANOUT_MODE_MAP.keys():
            self.cluster_type = CLUSTER_TYPE_TO_AF_PACKET_FANOUT_MODE_MAP.get(self.cluster_type)
        self.load_balance_processes = load_balance_processes
        self.pinned_cpus = list(pinned_cpus)

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                name=self.name,
                interface=self.interface,
                cluster_id=self.cluster_id,
                cluster_type=self.cluster_type,
                load_balance_processes=self.load_balance_processes,
                pinned_cpus=self.pinned_cpus,
                host=self.host
            )
        )

    def get_raw(self) -> Tuple[str, Dict]:
        return (self.name, dict(
            type=self.type,
            interface=f'af_packet::{self.interface}',
            lb_method='custom',
            af_packet_fanout_id=str(self.cluster_id),
            af_packet_fanout_mode=f'AF_Packet::{self.cluster_type}',
            lb_procs=str(self.load_balance_processes),
            pin_cpus=','.join([str(cpu) for cpu in self.pinned_cpus]),
            host=self.host
        ))


class Loggers(BaseComponents):
    def __init__(self, loggers: Optional[List[Logger]] = None):
        """
        A collection of one or more loggers

        Args:
            loggers: A Logger object
        """
        super().__init__(components=loggers)

    def get(self, name) -> Optional[Logger]:
        return super(Loggers, self).get(name)

    def add_logger(self, logger: Logger):
        super().add(logger)


class Proxies(BaseComponents):
    """
    A collection of one or more proxies

    Args:
        proxies: A Proxy object
    """
    def __init__(self, proxies: Optional[List[Proxy]] = None):
        super().__init__(components=proxies)

    def get(self, name) -> Optional[Proxy]:
        return super(Proxies, self).get(name)

    def add_proxy(self, proxy: Proxy):
        super().add(proxy)


class Workers(BaseComponents):

    def __init__(self, workers: Optional[List[Worker]] = None):
        """
        A collection of one or more workers

        Args:
            workers: A Worker object
        """
        super().__init__(components=workers)

    def get(self, name) -> Optional[Worker]:
        return super(Workers, self).get(name)

    def add_worker(self, worker: Worker):
        super().add(worker)
