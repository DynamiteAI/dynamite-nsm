import json
from typing import Optional, List

from dynamite_nsm.services.base.config_objects.generic import GenericItem, GenericItemGroup

IPV4_AND_CIDR_PATTERN = r'(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))'
IPV6_AND_CIDR_PATTERN = r'^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}' \
                        r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                        r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                        r'(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                        r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                        r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::' \
                        r'(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                        r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:' \
                        r'(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::' \
                        r'(?:[0-9A-Fa-f]{1,4}:)' \
                        r'{2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                        r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                        r'(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:' \
                        r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                        r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                        r'(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::' \
                        r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                        r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                        r'(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|' \
                        r'(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::/\d{1,2}(?!\d|(?:\.\d)))'


class LocalNetwork(GenericItem):

    def __init__(self, ip_and_cidr: str, description: Optional[str] = None):
        """A local network denoted by a IP/CIDR
        Args:
            ip_and_cidr: An IP/CIDR string representing a local network.
            description: A description of that network's purpose
        """
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
        """Get a raw representation of this LocalNetwork
        Returns:
            An assignment statement that can be inserted directly into Zeek's networks.cfg
        """
        if self.description:
            return '{0: <64} {1}\n'.format(self.ip_and_cidr, self.description)
        return '{0: <64} {1}\n'.format(self.ip_and_cidr, 'Undocumented Network')


class LocalNetworks(GenericItemGroup):

    def __init__(self, local_networks: Optional[List[LocalNetwork]] = None):
        """A collection of LocalNetworks
        Args:
            local_networks: A collection of LocalNetwork objects
        """
        super().__init__('ip_and_cidr', local_networks)
        self.local_networks = self.items
        self._idx = 0

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                local_networks=[f'{local_network.ip_and_cidr} = {local_network.description}' for local_network in
                                self.local_networks]
            )
        )

    def get_raw(self) -> List[str]:
        """Get a list of LocalNetworks that can be inserted directly into the network.cfg file
        Returns:
            A list of local network assignments
        """
        return [local_network.get_raw() for local_network in self.local_networks]
