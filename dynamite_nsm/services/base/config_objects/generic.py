import json
from zlib import adler32
from typing import List, Optional


class GenericItem(object):
    pass


class GenericItemGroup:

    def __init__(self, identifier_attribute: str, items: Optional[List[GenericItem]] = None, ):
        self.identifier_attribute = identifier_attribute
        self.items = items
        if items is None:
            self.items = []
        self._idx = 0

    def __add__(self, item: GenericItem) -> None:
        self.items.append(item)

    def __getitem__(self, identifier_value_str: str):
        for item in self.items:
            if getattr(item, self.identifier_attribute) == identifier_value_str:
                return item
        raise KeyError(f'{identifier_value_str} not found for any {self.identifier_attribute}')

    def __iter__(self):
        return self

    def __next__(self) -> GenericItem:
        if self._idx >= len(self.items):
            raise StopIteration
        current_item = self.items[self._idx]
        self._idx += 1
        return current_item

    def add(self, item: GenericItem) -> None:
        self.__add__(item)

    def remove(self, identifier_value_str: str):
        for i, item in enumerate(self.items):
            if getattr(item, self.identifier_attribute) == identifier_value_str:
                del self.items[i]
                return
        raise KeyError(f'{identifier_value_str} not found for any {self.identifier_attribute}')

    def get_raw(self) -> List[str]:
        return [item.get_raw() for item in self.items]


class Analyzer(GenericItem):

    def __init__(self, name: str, enabled: Optional[bool] = False):
        self.name = name
        self.id = adler32(str(name).encode("utf-8")) % 15000
        self.enabled = enabled

    def __str__(self):
        return json.dumps(dict(
            obj_name=str(self.__class__),
            id=self.id,
            name=self.name,
            enabled=self.enabled
        ))


class Analyzers(GenericItemGroup):

    def __init__(self, analyzers: Optional[List[Analyzer]] = None):
        super().__init__('name', analyzers)
        self.analyzers = self.items

    def get_disabled(self) -> List[Analyzer]:
        return [analyzer for analyzer in self.analyzers if not analyzer.enabled]

    def get_enabled(self) -> List[Analyzer]:
        return [analyzer for analyzer in self.analyzers if analyzer.enabled]

    def get_raw(self) -> List[str]:
        return [analyzer.name for analyzer in self.analyzers if analyzer.enabled]
