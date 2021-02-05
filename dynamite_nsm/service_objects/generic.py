import json
from typing import Optional, List


class Analyzer:

    def __init__(self, name: str, enabled: Optional[bool] = False):
        self.name = name
        self.enabled = enabled

    def __str__(self):
        return json.dumps(dict(
            obj_name=str(self.__class__),
            name=self.name,
            enabled=self.enabled
        ))


class Analyzers:

    def __init__(self, analyzers: Optional[List[Analyzer]] = None):
        self.analyzers = analyzers

        if analyzers is None:
            self.analyzers = []
        self._idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._idx >= len(self.analyzers):
            raise StopIteration
        current_analyzer = self.analyzers[self._idx]
        self._idx += 1
        return current_analyzer

    def add_analyzer(self, analyzer: Analyzer) -> None:
        self.analyzers.append(analyzer)

    def get_by_name(self, name: str) -> Optional[Analyzer]:
        for analyzer in self.analyzers:
            if analyzer.name == name:
                return analyzer
        return None

    def get_disabled(self) -> List[Analyzer]:
        return [analyzer for analyzer in self.analyzers if not analyzer.enabled]

    def get_enabled(self) -> List[Analyzer]:
        return [analyzer for analyzer in self.analyzers if analyzer.enabled]

    def get_raw(self) -> List[str]:
        return [analyzer.name for analyzer in self.analyzers if analyzer.enabled]
