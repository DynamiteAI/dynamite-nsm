import json
from typing import Dict, List, Optional, Union, Set

AF_PACKET_FANOUT_MODE_TO_CLUSTER_TYPE_MAP = dict(
    FANOUT_HASH='cluster_flow',
    FANOUT_CPU='cluster_cpu',
    FANOUT_QM='cluster_qm'
)


class PcapInterfaces:

    def __init__(self, interface_names: List[str]):
        """
        :param interface_names: A list of network interface names
        """
        self.interfaces = interface_names

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                interfaces=self.interfaces
            )
        )

    def get_raw(self) -> List[Dict]:
        return [dict(interface=interface) for interface in self.interfaces]


class AfPacketInterface:

    def __init__(self, interface_name: str, cluster_id: Optional[int] = None, cluster_type: Optional[str] = None,
                 bpf_filter: Optional[str] = None,
                 threads: Union[int, str] = None):

        """Suricata AF_PACKET interface
        Args:
            interface_name: The name of a network interface to monitor
            cluster_id: A unique integer associated with this worker maps to af_packet_fanout_id
            cluster_type: The algorithm used to spread traffic between sockets.
            bpf_filter: A filter that can be used to drop packets before they are analyzed
            threads: The number of threads dedicated to monitoring this network interface
        """
        self.interface = interface_name
        self.cluster_id = cluster_id
        if cluster_type:
            self.cluster_type = cluster_type.replace('AF_Packet::', '')
            if self.cluster_type in AF_PACKET_FANOUT_MODE_TO_CLUSTER_TYPE_MAP.keys():
                self.cluster_type = AF_PACKET_FANOUT_MODE_TO_CLUSTER_TYPE_MAP.get(self.cluster_type)
        else:
            self.cluster_type = 'cluster_qm'

        self.bpf_filter = bpf_filter
        self.threads = threads
        if not threads:
            self.threads = 'auto'

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                interface=self.interface,
                cluster_id=self.cluster_id,
                cluster_type=self.cluster_type,
                bpf_filter=self.bpf_filter,
                threads=self.threads
            )
        )

    def get_raw(self) -> Dict:
        """Get a raw representation of this AfPacketInterface.

        Returns:
            A dictionary that can be serialized to YAML then inserted into the `suricata.yaml` file.
        """
        orig_raw = {
            'interface': self.interface,
            'cluster-id': self.cluster_id,
            'cluster-type': self.cluster_type,
            'bpf-filter': self.bpf_filter,
            'threads': self.threads
        }
        orig_raw = {k: v for k, v in orig_raw.items() if v is not None and v != ''}
        return orig_raw


class AfPacketInterfaces:

    def __init__(self, interfaces: Optional[List[AfPacketInterface]] = None):
        """A collection of AfPacketInterfaces.
        Args:
            interfaces: A list of AfPacketInterface objects
        """
        self._idx = 0
        self.interfaces = interfaces
        if not self.interfaces:
            self.interfaces = []

    def __iter__(self):
        return self

    def __next__(self) -> AfPacketInterface:
        if self._idx >= len(self.interfaces):
            raise StopIteration
        current_interface = self.interfaces[self._idx]
        self._idx += 1
        return current_interface

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                interfaces=[
                    interface.interface for interface in self.interfaces
                ]
            )
        )

    def add(self, interface: AfPacketInterface) -> None:
        """Add a new AfPacketInterface
        Args:
            interface: An AfPacketInterface object

        Returns:
            None
        """
        self.interfaces.append(interface)

    def get(self, interface_name: str) -> Optional[AfPacketInterface]:
        """Given the name of an interface retrieve the corresponding AfPacketInterface object
        Args:
            interface_name: The name of the network interface.
        Returns:
            An AfPacketInterface if found, otherwise `None`
        """
        for interface in self.interfaces:
            if interface.interface == interface_name:
                return interface
        return None

    def remove(self, interface_name: str) -> None:
        """Given the name of an interface delete it
        Args:
            interface_name: The name of the network interface.
        Returns:
            None
        """
        temp_interfaces = []
        for interface in self.interfaces:
            if interface.interface == interface_name:
                continue
            temp_interfaces.append(interface)
        self.interfaces = temp_interfaces

    def get_raw(self) -> List[Dict]:
        """Get a raw representation of AfPacketInterfaces that can be serialized and inserted into `suricata.yaml` file
        Returns:
            A list of dictionaries representing individual AfPacketInterface configurations
        """
        return [interface.get_raw() for interface in self.interfaces]


class Threading:

    def __init__(self, management_cpu_set: Optional[Set] = None, receive_cpu_set: Optional[Set] = None,
                 worker_cpu_set: Optional[Set] = None):

        """The threading configuration for Suricata
        Args:
            management_cpu_set: A set of integers representing CPU cores dedicated to management tasks
            receive_cpu_set: A set of integers representing CPU cores dedicated to packet acquisition
            worker_cpu_set: A set of integers representing CPU cores dedicated to analysis
        """

        self.management_cpu_set = management_cpu_set
        self.receive_cpu_set = receive_cpu_set
        self.worker_cpu_set = worker_cpu_set

    def get_raw(self) -> Dict:
        """Get a raw representation of Threading that can be serialized and inserted into `suricata.yaml` file
        Returns:
            A dictionary containing the threading families
        """
        thread_families = []
        if self.management_cpu_set:
            thread_families.append(
                {
                    'management-cpu-set': {
                        'cpu': list(self.management_cpu_set)
                    }
                }
            )
        if self.receive_cpu_set:
            thread_families.append(
                {
                    'receive-cpu-set': {
                        'cpu': list(self.receive_cpu_set)
                    }
                }
            )
        if self.worker_cpu_set:
            thread_families.append(
                {
                    'worker-cpu-set': {
                        'cpu': list(self.worker_cpu_set),
                        'mode': 'exclusive',
                        'threads': len(self.worker_cpu_set)
                    }
                }
            )
        return {
            'set-cpu-affinity': True,
            'cpu-affinity': thread_families
        }
