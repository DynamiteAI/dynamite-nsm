import argparse

from typing import Any, Dict, Optional

RESERVED_VARIABLE_NAMES = ['config_data', 'extract_tokens', 'formatted_data', 'stdout', 'verbose', 'logger',
                           'out_file_path', 'backup_directory', 'top_text', 'interface', 'sub_interface',
                           'config_module', 'filebeat_config_path']


class BaseInterface:
    """
    An abstract interface used primarily in instance checks
    """
    def __init__(self, interface_name: Optional[str] = None, interface_description: Optional[str] = None,
                 defaults: Optional[Dict] = None):
        """
        Setup the interface
        Args:
            interface_name: A descriptive name of the interface
            interface_description: A description of what the utility does
            defaults: Any arguments and their value you wish to default (E.G stdout=True)
        """
        self.interface_name = interface_name
        self.interface_description = interface_description
        self.defaults = defaults
        if not self.defaults:
            self.defaults = dict()

    def get_parser(self) -> argparse.ArgumentParser:
        """
        Returns: an `ArgumentParser` instance
        """
        raise NotImplementedError()

    def execute(self, args: argparse.Namespace) -> Any:
        """Interpret the parsed arguments and execute using the proper `service.action` class; can return any value.
        Args:
            args: `argparse.Namespace` created by a method such as `argparse.ArgumentParser().parse_args()`

        Returns: Can return any value; completely depends on the `service.action` being invoked

        """
        raise NotImplementedError()
