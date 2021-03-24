import argparse

from typing import Optional

from dynamite_nsm.services.base.config_objects import generic
from dynamite_nsm.cmd.inspection_helpers import ArgparseParameters


class AnalyzerInterface:

    def __init__(self, config_obj: generic.Analyzer, interface_name: str, interface_description: Optional[str] = None):
        self.config_obj = config_obj
        self.interface_name = interface_name
        self.interface_description = interface_description
        self.analyzer_value = getattr(self.config_obj, 'value', None)

    def get_parser(self):
        parser = argparse.ArgumentParser(description=f'{self.interface_name} - {self.interface_description}')
        parser.add_argument('--enable', dest='enabled', action='store_true', help=f'Enable {self.config_obj.name}')
        parser.add_argument('--disable', dest='enabled', action='store_false', help=f'Disable {self.config_obj.name}')
        if self.analyzer_value:
            parser.add_argument('--value', dest='value', type=str, default=self.analyzer_value,
                                help=f'The value associated with: {self.config_obj.name}')
        return parser

    def execute(self, args: argparse.Namespace) -> generic.Analyzer:
        self.config_obj.enabled = args.enabled
        if self.analyzer_value:
            self.config_obj.value = args.value
        return self.config_obj

