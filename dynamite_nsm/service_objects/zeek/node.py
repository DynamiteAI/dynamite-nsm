import json
from typing import Dict, List, Optional, Tuple

CLUSTER_TYPE_TO_AF_PACKET_FANOUT_MODE_MAP = dict(
    cluster_flow='FANOUT_HASH',
    cluster_cpu='FANOUT_CPU',
    cluster_qm='FANOUT_QM'
)


class BaseComponent:

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
    

class BaseComponents:
    
    def __init__(self, components: Optional[List[BaseComponent]] = None):
        self._idx = 0
        self.components = components
        if not self.components:
            self.components = []

    def __iter__(self):
        return self

    def __next__(self) -> BaseComponent:
        if self._idx >= len(self.components):
            raise StopIteration
        current_component = self.components[self._idx]
        self._idx += 1
        return current_component

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                components=[component.name for component in self.components]
            )
        )

    def add_component(self, component: BaseComponent) -> None:
        """
        Add a new component

        :param component: A component instance to add
        """
        self.components.append(component)

    def remove_by_name(self, component_name: str) -> None:
        """
        Remove a component instance by name

        :param component_name: The name of the component to remove
        """
        temp_components = []
        for component in self.components:
            if component.component_name == component_name:
                continue
            temp_components.append(component)
        self.components = temp_components

    def get_raw(self) -> List[Tuple[str, Dict]]:
        return [component.get_raw() for component in self.components]


class Logger(BaseComponent):

    def __init__(self, logger_name: str, host: str):
        super().__init__(logger_name, 'logger', host)


class Manager(BaseComponent):

    def __init__(self, manager_name: str, host: str):
        super().__init__(manager_name, 'manager', host)


class Proxy(BaseComponent):
    
    def __init__(self, proxy_name: str, host: str):
        super().__init__(proxy_name, 'proxy', host)


class Worker(BaseComponent):

    def __init__(self, worker_name: str, interface_name: str, cluster_id: int, cluster_type: str,
                 load_balance_processes: Optional[int] = 1, pinned_cpus: Optional[Tuple[int]] = (0,),
                 host: Optional[str] = 'localhost'):
        """
        A Zeek worker process

        :param worker_name: The name of the worker
        :param interface_name: The name of a network interface
        :param cluster_id: A unique integer associated with this worker maps to af_packet_fanout_id
        :param cluster_type: The algorithm used to spread traffic between sockets. cluster_flow (FANOUT_HASH),
                             cluster_cpu (FANOUT_CPU), cluster_qm (FANOUT_QM). Maps to af_packet_fanout_mode
        :param load_balance_processes: The number of Zeek processes associated with a given worker
        :param pinned_cpus: Core affinity for the processes (iterable),
        :param host: The host on which the worker is running
        """
        super().__init__(worker_name, 'worker', host)

        self.name = worker_name
        self.interface = interface_name.replace('af_packet::', '')
        self.cluster_id = cluster_id
        self.cluster_type = cluster_type
        if cluster_type not in CLUSTER_TYPE_TO_AF_PACKET_FANOUT_MODE_MAP.keys():
            self.cluster_type = CLUSTER_TYPE_TO_AF_PACKET_FANOUT_MODE_MAP.get(cluster_type, 'cluster_flow').replace(
                'AF_PACKET::', '')
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
            af_packet_fanout_mode=f'AF_PACKET::{self.cluster_type}',
            lb_procs=str(self.load_balance_processes),
            pinned_cpus=','.join([str(cpu) for cpu in self.pinned_cpus]),
            host=self.host
        ))


class Loggers(BaseComponents):
    def __init__(self, loggers: Optional[List[Logger]] = None):
        super().__init__(components=loggers)

    def add_logger(self, logger: Logger):
        super().add_component(logger)


class Proxies(BaseComponents):
    def __init__(self, proxies: Optional[List[Proxy]] = None):
        super().__init__(components=proxies)

    def add_proxy(self, proxy: Proxy):
        super().add_component(proxy)


class Workers(BaseComponents):

    def __init__(self, workers: Optional[List[Worker]] = None):
        super().__init__(components=workers)

    def add_worker(self, worker: Worker):
        super().add_component(worker)
