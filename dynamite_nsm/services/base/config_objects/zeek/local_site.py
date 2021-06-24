import json
from typing import Optional, List

from dynamite_nsm.services.base.config_objects.generic import Analyzer, Analyzers


class Definition(Analyzer):

    def __init__(self, name: str, value: str, enabled: Optional[bool] = False):
        """A global variable applied at runtime.
        Args:
            name: The name of the definition
            value: The value associated with the definition
            enabled: Whether or not this definition should be enabled
        """
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
        """Get a raw representation of this Definition
        Returns:
            A redef statement that can be inserted into Zeek's site/local.zeek
        """
        if self.enabled:
            return f'redef {self.name} = {self.value}'
        return f'#redef {self.name} = {self.value}'


class Definitions(Analyzers):

    def __init__(self, definitions: List[Definition] = None):
        """A collection of Definitions
        Args:
            definitions: A collection of Definition objects
        """
        super().__init__(definitions)
        self.definitions = self.analyzers

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                scripts=[f'{definition.name} (enabled: {definition.enabled}) = {definition.value}' for definition in
                         self.definitions]
            )
        )

    def get_raw(self) -> List[str]:
        """Get a list of all the Definitions that can be inserted directly into the site/local.zeek file
        Returns:
            A list of redef statements
        """
        return [definition.get_raw() for definition in self.definitions]


class Script(Analyzer):

    def __init__(self, name: str, enabled: Optional[bool] = False):
        """A script that performs some form of analysis
        Args:
            name: The name of the definition
            enabled: Whether or not this script should be enabled
        """
        self.value = None
        super().__init__(name, enabled)

    def get_raw(self) -> str:
        """Get a raw representation of this Script
        Returns:
            A @load statement that can be inserted into Zeek's site/local.zeek
        """
        if self.enabled:
            return f'@load {self.name}'
        return f'#@load {self.name}'


class Scripts(Analyzers):

    def __init__(self, scripts: Optional[List[Script]] = None):
        """A collection of Scripts
        Args:
            scripts: A collection of Script objects
        """
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
        """Get a list of all the Scripts that can be inserted directly into the site/local.zeek file
        Returns:
            A list of @load statements
        """
        return [script.get_raw() for script in self.scripts]


class Signature(Analyzer):

    def __init__(self, name: str, enabled: Optional[bool] = False):
        """A signature set made available at runtime.
        Args:
            name: The name of the signature
            enabled: Whether or not this definition should be enabled
        """
        self.value = None
        super().__init__(name, enabled)

    def get_raw(self) -> str:
        """Get a raw representation of this Signature
        Returns:
            A @load-sig statement that can be inserted into Zeek's site/local.zeek
        """
        if self.enabled:
            return f'@load-sigs {self.name}'
        return f'#@load-sigs {self.name}'


class Signatures(Analyzers):

    def __init__(self, signatures: Optional[List[Signature]] = None):
        """A collection of Signatures
        Args:
            signatures: A collection of Signature objects
        """
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
        """Get a list of all the Signatures that can be inserted directly into the site/local.zeek file
        Returns:
            A list of @load-sigs statements
        """
        return [signature.get_raw() for signature in self.signatures]
