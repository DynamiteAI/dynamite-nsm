import argparse
from typing import Any

from tabulate import tabulate

from dynamite_nsm.cmd.base_interface import BaseInterface
from dynamite_nsm.services.base.config_objects import generic

"""
Commandline interface wrappers for services.base.config_objects
"""


class AnalyzersInterface(BaseInterface):
    """
    Provides a commandline interface wrapper for any services.base.config_objects.generic.Analyzers derived class
    are derived:
        - services.base.config_objects.zeek.local_site.Definitions
        - services.base.config_objects.zeek.local_site.Signatures
        - services.base.config_objects.zeek.local_site.Scripts
        - services.base.config_objects.suricata.rules.Rules
    """

    def __init__(self, config_obj: generic.Analyzers):
        super().__init__()
        self.config_obj = config_obj

    def get_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser()
        choices = []
        for analyzer in self.config_obj.analyzers:
            choices.append(analyzer.id)
        parser.add_argument('--id', dest='analyzer_id', type=int,
                            help='Specify the id for the config object you want to work with.',
                            choices=choices)
        parser.add_argument('--enable', dest='enable', action='store_true', help=f'Enable selected object.')
        parser.add_argument('--disable', dest='disable', action='store_true', help=f'Disable selected object')
        if getattr(self.config_obj.analyzers[0], 'value', None):
            parser.add_argument('--value', dest='value', type=str,
                                help=f'The value associated with the selected object')

        return parser

    def execute(self, args: argparse.Namespace) -> Any:
        selected_analyzer = None
        selected_analyzer_value = 'N/A'
        headers = ['Id', 'Name', 'Enabled', 'Value']
        table = [headers]
        for analyzer in self.config_obj.analyzers:
            analyzer_value = 'N/A'
            if getattr(analyzer, 'value', None):
                analyzer_value = analyzer.value
            row = [analyzer.id, analyzer.name, analyzer.enabled, analyzer_value]
            table.append(row)
            if analyzer.id == args.analyzer_id:
                selected_analyzer = analyzer
                selected_analyzer_value = analyzer_value
                break
        if not args.analyzer_id:
            return tabulate(table, tablefmt='fancy_grid')
        else:
            if selected_analyzer:
                if args.disable:
                    selected_analyzer.enabled = False
                elif args.enable:
                    selected_analyzer.enabled = True

                if getattr(selected_analyzer, 'value',
                           None) and args.value:  # TODO smells bad - check class implementation that requires this hack
                    selected_analyzer.value = args.value
                else:
                    # Populate value in the namespace so we can perform the below check w/o issue.
                    args.value = None

                if not args.value and not args.enable and not args.disable:
                    table = [headers, [selected_analyzer.id, selected_analyzer.name, selected_analyzer.enabled,
                                       selected_analyzer_value]]
                    return tabulate(table, tablefmt='fancy_grid')
        return self.config_obj


def append_config_object_analyzer_interface_to_parser(parser: argparse.ArgumentParser, interface: AnalyzersInterface):
    choices = []
    for analyzer in interface.config_obj.analyzers:
        choices.append(analyzer.id)
    parser.add_argument('--id', dest='analyzer_id', type=int,
                        help='Specify the id for the config object you want to work with.',
                        choices=choices)
    parser.add_argument('--enable', dest='enable', action='store_true', help=f'Enable selected object.')
    parser.add_argument('--disable', dest='disable', action='store_true', help=f'Disable selected object')
    if getattr(interface.config_obj.analyzers[0], 'value', None):
        parser.add_argument('--value', dest='value', type=str,
                            help=f'The value associated with the selected object')
    return parser
