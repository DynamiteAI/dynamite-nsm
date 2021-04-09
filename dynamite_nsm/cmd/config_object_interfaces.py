import argparse
from typing import Any, Dict, Optional

from tabulate import tabulate

from dynamite_nsm.cmd.base_interface import BaseInterface
from dynamite_nsm.cmd.base_interface import RESERVED_VARIABLE_NAMES
from dynamite_nsm.cmd.inspection_helpers import ArgparseParameters
from dynamite_nsm.cmd.inspection_helpers import get_function_definition
from dynamite_nsm.services.base.config_objects import generic
from dynamite_nsm.services.base.config_objects.filebeat import targets

"""
Commandline interface wrappers for services.base.config_objects
"""


class AnalyzersInterface(BaseInterface):
    """
    Convert any `generic.Analyzers` derived class into a commandline utility (E.G Zeek scripts, signatures, and redefs
    as well as Suricata signatures
    """

    def __init__(self, config_obj: generic.Analyzers):
        """
        Setup the interface

        Args:
            config_obj: A complex config object that contains one or more `Analyzers`
        """
        super().__init__()
        self.config_obj = config_obj
        self.changed_rows = []

    def get_parser(self) -> argparse.ArgumentParser:
        """ For the given interface return an `argparse.ArgumentParser` object for a Zeek Script, Definition, or Signature
        or a Suricata signature.

        Returns: An argparse.ArgumentParser instance for the instantiated `AnalyzerInterface`
        """
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
        """Interpret the parsed arguments and execute using the proper `service.action` class; can return any value.
        Args:
            args: `argparse.Namespace` created by a method such as `argparse.ArgumentParser().parse_args()`

        Returns: Can return any value; completely depends on the `service.action` being invoked
        """
        self.changed_rows = []
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
                    if not str(args.value).endswith(';'):
                        args.value = args.value + ';'
                    selected_analyzer.value = args.value
                else:
                    # Populate value in the namespace so we can perform the below check w/o issue.
                    args.value = None

                if not args.value and not args.enable and not args.disable:
                    table = [headers, [selected_analyzer.id, selected_analyzer.name, selected_analyzer.enabled,
                                       selected_analyzer_value]]
                    return tabulate(table, tablefmt='fancy_grid')
                else:
                    changed_value = selected_analyzer_value
                    if args.value:
                        changed_value = args.value
                    self.changed_rows = [[selected_analyzer.id, selected_analyzer.name, selected_analyzer.enabled,
                                          changed_value]]
                    return self.config_obj


class FilebeatTargetsInterface(BaseInterface):
    """
    Convert any Filebeat `BaseTargets` derived class into a commandline utility.
    """

    def __init__(self, config_obj: targets.BaseTargets, defaults: Optional[Dict] = None):
        """
        Setup the interface
        Args:
            config_obj: A Filebeat specific complex config object that specifies a downstream target config - where
            to send logs.
            defaults: Any default commandline arguments you wish to define ahead of time `dict(arg_name=arg_value)`
        """
        super().__init__(defaults=defaults)
        self.config_obj = config_obj
        self.changed_rows = []

    def _get_description_for_instance_var(self, var: str):
        from docstring_parser import parse as docstring_parse
        _, _, docs = get_function_definition(func=self.config_obj.__init__)
        for param in docstring_parse(docs).params:
            if param.arg_name == var:
                return param.description
        return ''

    def get_parser(self):
        """ For the given interface return an `argparse.ArgumentParser` object for a Filebeat `BaseTargets` object
        Returns: An argparse.ArgumentParser instance for the instantiated `BaseTargets` derived class
        """
        parser = argparse.ArgumentParser()
        target_options = parser.add_argument_group('target options')
        for var in vars(self.config_obj):
            args = ArgparseParameters.create_from_typing_annotation(var, type(getattr(self.config_obj, var)))
            if var != 'enabled':
                arg_description = self._get_description_for_instance_var(var).replace('\n', ' ')
            else:
                arg_description = 'If included, this target will be enabled, and events sent to it.'
            args.add_description(arg_description)
            try:
                target_options.add_argument(*args.flags, **args.kwargs)
            except argparse.ArgumentError:
                continue
        return parser

    def execute(self, args: argparse.Namespace) -> Any:
        """Interpret the parsed arguments and execute using the proper `service.action` class; can return any value.
        Args:
            args: `argparse.Namespace` created by a method such as `argparse.ArgumentParser().parse_args()`

        Returns: Can return any value; completely depends on the `service.action` being invoked
        """
        self.changed_rows = []
        changed_config = False
        headers = ['Config Option', 'Value']
        table = [headers]
        for option, value in args.__dict__.items():
            if option in self.defaults:
                continue
            if option in RESERVED_VARIABLE_NAMES:
                continue
            if not value:
                config_value = (option, getattr(self.config_obj, option, None))
                if not config_value[1]:
                    config_value = option, 'N/A'
                table.append(config_value)
            else:
                changed_config = True
                self.changed_rows.append([option, value])
                setattr(self.config_obj, option, value)
        if not changed_config:
            return tabulate(table, tablefmt='fancy_grid')
        return self.config_obj


def append_config_object_analyzer_interface_to_parser(parser: argparse.ArgumentParser,
                                                      interface: AnalyzersInterface) -> argparse.ArgumentParser:
    """Append an `AnalyzersInterface` interface into an existing parser.
    Args:
        parser: The `argparse.ArgumentParser` instance that you want to add a new parser too
        interface: The `AnalyzerInterface` instance you wish to append

    Returns: The modified parser
    """
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


def append_config_object_filebeat_targets_to_parser(parser: argparse.ArgumentParser,
                                                    interface: FilebeatTargetsInterface) -> argparse.ArgumentParser:
    """Append an `FilebeatTargetsInterface` interface into an existing parser.
    Args:
        parser: The `argparse.ArgumentParser` instance that you want to add a new parser too
        interface: The `FilebeatTargetsInterface` instance you wish to append

    Returns: The modified parser
    """
    target_options = parser.add_argument_group('target options')
    for var in vars(interface.config_obj):
        args = ArgparseParameters.create_from_typing_annotation(var, type(getattr(interface.config_obj, var)))
        arg_description = interface._get_description_for_instance_var(var).replace('\n', ' ')
        args.add_description(arg_description)
        try:
            target_options.add_argument(*args.flags, **args.kwargs)
        except argparse.ArgumentError:
            continue
    return parser
