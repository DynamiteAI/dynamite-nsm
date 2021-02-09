import json
from typing import Optional, List

from dynamite_nsm.service_objects.generic import Analyzer, Analyzers


class Definition(Analyzer):

    def __init__(self, name: str, value: str, enabled: Optional[bool] = False):
        super().__init__(name, enabled)
        self.value = value

    def __str__(self) -> str:
        return json.dumps(dict(
            obj_name=str(self.__class__),
            name=self.name,
            value=self.value,
            enabled=self.enabled
        ))

    def get_raw(self) -> str:
        if self.enabled:
            return f'redef {self.name} = {self.value}'
        return f'#redef {self.name} = {self.value}'


class Definitions(Analyzers):

    def __init__(self, scripts: List[Definition] = None):
        super().__init__(scripts)
        self.scripts = self.analyzers

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                scripts=[f'{script.name} (enabled: {script.enabled}) = {script.value}' for script in
                         self.scripts]
            )
        )

    def get_raw(self) -> List[str]:
        return [script.get_raw() for script in self.scripts]


class Script(Analyzer):

    def __init__(self, name: str, enabled: Optional[bool] = False):
        super().__init__(name, enabled)

    def get_raw(self) -> str:
        if self.enabled:
            return f'@load {self.name}'
        return f'#@load {self.name}'


class Scripts(Analyzers):

    def __init__(self, scripts: Optional[List[Script]] = None):
        super().__init__(scripts)
        self.scripts = self.analyzers

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                scripts=[f'{script.name} (enabled: {script.enabled})' for script in
                         self.scripts]
            )
        )

    def get_raw(self) -> List[str]:
        return [script.get_raw() for script in self.scripts]


class Signature(Analyzer):

    def __init__(self, name: str, enabled: Optional[bool] = False):
        super().__init__(name, enabled)

    def get_raw(self) -> str:
        if self.enabled:
            return f'@load-sig {self.name}'
        return f'#@load-sig {self.name}'


class Signatures(Analyzers):

    def __init__(self, signatures: Optional[List[Signature]] = None):
        super().__init__(signatures)
        self.signatures = self.analyzers

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                signatures=[f'{signature.name} (enabled: {signature.enabled})' for signature in
                            self.signatures]
            )
        )

    def get_raw(self) -> List[str]:
        return [signature.get_raw() for signature in self.signatures]
