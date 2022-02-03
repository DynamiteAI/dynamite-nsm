import json
from hashlib import sha256
from typing import List, Optional, Union


class GenericItem(object):
    """Empty Class"""
    pass


class GenericItemGroup:

    def __init__(self, identifier_attribute: str, items: Optional[List[GenericItem]] = None, ):
        """
        A base class representing simple groups of configuration options, where each group is unique.

        Args:
            identifier_attribute: The name of an attribute found within the GenericItem list used for identification
            items: A list of GenericItems
        """
        self.identifier_attribute = identifier_attribute
        self.items = items
        if items is None:
            self.items = []
        self._idx = 0

    def __add__(self, item: GenericItem) -> None:
        self.items.append(item)

    def __getitem__(self, indexing_value: Union[str, int]):
        if type(indexing_value) == int:
            return self.items[indexing_value]
        else:
            for item in self.items:
                if getattr(item, self.identifier_attribute) == indexing_value:
                    return item
            raise KeyError(f'{indexing_value} not found for any {self.identifier_attribute}')

    def add(self, item: GenericItem) -> None:
        self.__add__(item)

    def get(self, identifier_value_str: str) -> Optional[GenericItem]:
        for i, item in enumerate(self.items):
            if getattr(item, self.identifier_attribute) == identifier_value_str:
                return self.items[i]
        return None

    def remove(self, identifier_value_str: str):
        for i, item in enumerate(self.items):
            if getattr(item, self.identifier_attribute) == identifier_value_str:
                del self.items[i]
                return
        raise KeyError(f'{identifier_value_str} not found for any {self.identifier_attribute}')

    def get_raw(self) -> List[str]:
        return [item.get_raw() for item in self.items]


class Analyzer(GenericItem):
    """
    Analyzers are packages used for identifying Zeek scripts and signatures as well as Suricata rule-sets
    """
    def __init__(self, name: str, enabled: Optional[bool] = False, content: Optional[str] = None):
        """
        Create a simple analyzer object

        Args:
            name: The name (or often path) to the analyzer
            enabled: True, if enabled
            content: If included the contents of the analyzer will be used to generate a unique hash.
        """
        self.name = name
        self.enabled = enabled

        if not content:
            self.id = sha256(str(name).encode("utf-8")).hexdigest()[0:7]
        else:
            self.id = sha256(str(content).encode("utf-8")).hexdigest()[0:7]

    def __str__(self):
        return json.dumps(dict(
            obj_name=str(self.__class__),
            id=self.id,
            name=self.name,
            enabled=self.enabled
        ))


class Analyzers(GenericItemGroup):
    """A Group of Analyzers; provides some basic methods for filtering and display"""

    def __init__(self, analyzers: Optional[List[Analyzer]] = None):
        super().__init__('id', analyzers)
        self.analyzers = self.items

    def get_disabled(self) -> List[Analyzer]:
        """Get all analyzers that are disabled.
        Returns:
            A list of disabled `Analyzer` packages
        """
        return [analyzer for analyzer in self.analyzers if not analyzer.enabled]

    def get_enabled(self) -> List[Analyzer]:
        """Get all analyzers that are enabled.
        Returns:
            A list of enabled `Analyzer` packages
        """
        return [analyzer for analyzer in self.analyzers if analyzer.enabled]

    def get_raw(self) -> List[str]:
        """
        Get the analyzers in a format that can be directly written to a corresponding configuration
        Returns:
            A list of analyzer names.
        """
        return [analyzer.name for analyzer in self.analyzers if analyzer.enabled]
