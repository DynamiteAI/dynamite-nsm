import json
from typing import Dict, List, Optional, Union

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

    def get_raw(self) -> List:
        return [dict(interface=interface) for interface in self.interfaces]


class AfPacketInterface:

    def __init__(self, interface_name: str, cluster_id: Optional[int] = None, cluster_type: Optional[str] = None,
                 bpf_filter: Optional[str] = None,
                 threads: Union[int, str] = None):
        self.interface = interface_name
        self.cluster_id = cluster_id
        if cluster_type:
            self.cluster_type = cluster_type.replace('AF_Packet::', '')
            if self.cluster_type in AF_PACKET_FANOUT_MODE_TO_CLUSTER_TYPE_MAP.keys():
                self.cluster_type = AF_PACKET_FANOUT_MODE_TO_CLUSTER_TYPE_MAP.get(self.cluster_type)
        else:
            self.cluster_type = 'cluster_flow'

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

    def get_raw(self):
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
        self.interfaces.append(interface)

    def get(self, interface_name: str) -> Optional[AfPacketInterface]:
        for interface in self.interfaces:
            if interface.interface == interface_name:
                return interface
        return None

    def remove(self, interface_name: str) -> None:
        temp_interfaces = []
        for interface in self.interfaces:
            if interface.interface == interface_name:
                continue
            temp_interfaces.append(interface)
        self.interfaces = temp_interfaces

    def get_raw(self) -> List[Dict]:
        return [interface.get_raw() for interface in self.interfaces]