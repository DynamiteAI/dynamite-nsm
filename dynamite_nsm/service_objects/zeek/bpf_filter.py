import json
from typing import Optional, List


class BpfFilter:

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


class BpfFilters:

    def __init__(self, bpf_filters: Optional[List[BpfFilter]] = None):
        if bpf_filters is None:
            self.bpf_filters = []
        self._idx = 0

    def __add__(self, bpf_filter: BpfFilter) -> None:
        self.bpf_filters.append(bpf_filter)

    def __getitem__(self, interface_name: str):
        for bpf_filter in self.bpf_filters:
            if bpf_filter.name == interface_name:
                return bpf_filter
        raise KeyError(f'No interface named: {interface_name}')

    def __iter__(self):
        return self

    def __next__(self):
        if self._idx >= len(self.bpf_filters):
            raise StopIteration
        current_filter = self.bpf_filters[self._idx]
        self._idx += 1
        return current_filter
    
    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                bpf_filters=[f'{bpf_filter.name} = {bpf_filter.pattern}' for bpf_filter in self.bpf_filters]
            )
        )

    def add_bpf_filter(self, bpf_filter: BpfFilter) -> None:
        self.bpf_filters.append(bpf_filter)

    def get_raw(self) -> List[str]:
        return [bpf_filter.get_raw() for bpf_filter in self.bpf_filters]
