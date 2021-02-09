import json
from typing import Optional, List

from dynamite_nsm.service_objects.generic import GenericItem, GenericItemGroup


class BpfFilter(GenericItem):

    def __init__(self, interface_name, pattern):
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
        return f'{self.interface}\t{self.pattern}'


class BpfFilters(GenericItemGroup):

    def __init__(self, bpf_filters: Optional[List[BpfFilter]] = None):
        super().__init__('interface', bpf_filters)
        self.bpf_filters = self.items
        self._idx = 0
    
    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                bpf_filters=[f'{bpf_filter.interface} = {bpf_filter.pattern}' for bpf_filter in self.bpf_filters]
            )
        )
