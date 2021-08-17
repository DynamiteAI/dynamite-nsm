import json
from typing import Optional, List

from dynamite_nsm.services.base.config_objects.generic import GenericItem, GenericItemGroup


class BpfFilter(GenericItem):

    def __init__(self, interface_name: str, pattern: str):
        """
        Represents a BPF filter applied to a single network interface.
        Args:
            interface_name: The name of the network interface (E.G eth0, en0, mon0)
            pattern: A valid BPF filter (E.G udp dst port not 53)
        """
        self.interface = interface_name
        self.pattern = pattern

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                interface=self.interface,
                pattern=self.pattern
            )
        )

    def get_raw(self) -> str:
        """Get the representation of the value as it would appear the config.

        Returns:
            A line containing both the network interface and pattern associated with it.
        """
        return f'{self.interface}\t{self.pattern}'


class BpfFilters(GenericItemGroup):

    def __init__(self, bpf_filters: Optional[List[BpfFilter]] = None):
        """A collection of BpfFilters
        Args:
            bpf_filters: A collection of BpfFilter objects
        """
        super().__init__('interface', bpf_filters)
        self.bpf_filters = self.items
        self._idx = 0

    def get(self, interface) -> Optional[BpfFilter]:
        return super(BpfFilters, self).get(interface)
    
    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                bpf_filters=[f'{bpf_filter.interface} = {bpf_filter.pattern}' for bpf_filter in self.bpf_filters]
            )
        )
