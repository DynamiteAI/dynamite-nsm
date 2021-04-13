import argparse

from typing import Dict, Optional

RESERVED_VARIABLE_NAMES = ['config_data', 'extract_tokens', 'formatted_data', 'stdout', 'verbose', 'logger',
                           'out_file_path', 'backup_directory', 'top_text', 'interface', 'sub_interface',
                           'config_module', 'filebeat_config_path']


class BaseInterface:

    def __init__(self, interface_name: Optional[str] = None, interface_description: Optional[str] = None,
                 defaults: Optional[Dict] = None):
        self.interface_name = interface_name
        self.interface_description = interface_description
        self.defaults = defaults
        if not self.defaults:
            self.defaults = dict()

    def get_parser(self):
        raise NotImplementedError()

    def execute(self, args: argparse.Namespace):
        raise NotImplementedError()
