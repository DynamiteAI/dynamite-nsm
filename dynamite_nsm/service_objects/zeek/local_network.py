import json
from typing import Optional, List

from dynamite_nsm.service_objects.generic import GenericItem, GenericItemGroup


class LocalNetwork(GenericItem):

    def __init__(self, ip_and_cidr: str, description: Optional[str] = None):
        self.ip_and_cidr = ip_and_cidr
        self.description = description

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                ip_and_cidr=self.ip_and_cidr,
                description=self.description
            )
        )

    def get_raw(self) -> str:
        if self.description:
            return '{0: <64} {1}\n'.format(self.ip_and_cidr, self.description)
        return '{0: <64} {1}\n'.format(self.ip_and_cidr, 'Undocumented Network')


class LocalNetworks(GenericItemGroup):

    def __init__(self, local_networks: Optional[List[LocalNetwork]] = None):
        super().__init__('ip_and_cidr')
        if local_networks is None:
            self.local_networks = []
        self._idx = 0

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                local_networks=[f'{local_network.name} = {local_network.pattern}' for local_network in
                                self.local_networks]
            )
        )

    def get_raw(self) -> List[str]:
        return [local_network.get_raw() for local_network in self.local_networks]
