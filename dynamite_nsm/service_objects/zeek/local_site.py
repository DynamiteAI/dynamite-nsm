import json
from typing import Optional, List

from dynamite_nsm.service_objects.generic import Analyzer, Analyzers


class Definition(Analyzer):

    def __init__(self, name: str, value: str, enabled: Optional[bool] = False):
        super().__init__(name, enabled)
        self.value = value

    def __str__(self):
        return json.dumps(dict(
            obj_name=str(self.__class__),
            name=self.name,
            value=self.value,
            enabled=self.enabled
        ))


class Definitions(Analyzers):

    def __init__(self, definitions: Definition):
        self.definitions = definitions


class Script(Analyzer):

    def __init__(self, name: str, enabled: Optional[bool] = False):
        super().__init__(name, enabled)


class Signature(Analyzer):

    def __init__(self, name: str, enabled: Optional[bool] = False):
        super().__init__(name, enabled)


class Scripts(Analyzers):

    def __init__(self, scripts: Optional[List[Script]] = None):
        super().__init__(scripts)
        self.scripts = self.analyzers

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                scripts=[script.name for script in self.scripts]
            )
        )

    def add_script(self, script: Script):
        self.add_analyzer(script)
        self.scripts = self.analyzers


class Signatures(Analyzers):

    def __init__(self, signatures: Optional[List[Signature]] = None):
        super().__init__(signatures)
        self.signatures = self.analyzers

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                signatures=[signature.name for signature in self.signatures]
            )
        )

    def add_signature(self, signature: Signature):
        self.add_analyzer(signature)
        self.signatures = self.analyzers

