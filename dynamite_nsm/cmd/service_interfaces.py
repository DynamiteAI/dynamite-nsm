from __future__ import annotations

import argparse
import inspect
from typing import Any, Dict, List, Optional, Union

import daemon
from tabulate import tabulate

from dynamite_nsm.cmd import interface_operations
from dynamite_nsm.cmd.base_interface import BaseInterface
from dynamite_nsm.cmd.base_interface import RESERVED_VARIABLE_NAMES
from dynamite_nsm.cmd.config_object_interfaces import AnalyzersInterface, FilebeatTargetsInterface, \
    SuricataInterfaceConfigObjectsInterface, ZeekNodeConfigObjectInterface, ZeekNodeConfigObjectsInterface
from dynamite_nsm.cmd.inspection_helpers import ArgparseParameters
from dynamite_nsm.cmd.inspection_helpers import get_class_instance_methods
from dynamite_nsm.services.base import config
from dynamite_nsm.services.base.config_objects.zeek import node
from dynamite_nsm.services.base.config_objects.suricata import misc
from dynamite_nsm.services.base.config_objects.filebeat import targets
from dynamite_nsm.services.base.config_objects.generic import Analyzers

"""
Commandline interface wrappers for services
"""


class MultipleResponsibilityInterface(BaseInterface):
    """
    Maps a class with several responsibilities to commandline interface
    For example ProcessManager's provides multiple methods that can be invoked to perform various tasks.

    MultipleResponsibilityInterface:

    1. Takes a single class and supported_method_names.
    2. Uses several introspection techniques to enumerate instance methods from that class
    3. Derives the **kwargs params for argparse.ArgumentParser.add_arguments method for the __init__, and
       selected exec_method
    4. Generates parser using annotation and docs
    5. Provide a method for executing the parsed argparse.Namespace against
       cls.__init__(**base_kwargs).{exec_method(**interface_kwargs)}
    """

    def __init__(self, cls: object, supported_method_names: List[str], interface_name: str,
                 interface_description: Optional[str] = None, defaults: Optional[Dict] = None):
        """Initialize the interface
        Args:
            cls: The class we wish to turn into a commandline utility
            supported_method_names: A list of methods to create interfaces for
            interface_name: The name of this commandline interface
            interface_description: A description of what this interface is supposed to do
            defaults: A dictionary where the key a parameter name and the value represents the value to default too.
        """

        super().__init__(interface_name, interface_description, defaults=defaults)
        self.cls = cls
        self.supported_method_names = supported_method_names
        if not interface_description:
            self.interfaceModuleType_description = inspect.getdoc(cls)
        self.base_params, self.interface_methods = get_class_instance_methods(cls, defaults, use_parent_init=False)
        # print(self.cls, [(item.name, item.flags, item.kwargs) for item in self.base_params])

    @staticmethod
    def build_parser(interface: MultipleResponsibilityInterface,
                     parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
        """Build a parser from any `MultipleResponsibilityInterface` and `argparse.ArgumentParser` derived class
        Args:
            parser: The `argparse.ArgumentParser` instance that you want to add a new parser too
            interface: The `MultipleResponsibilityInterface` instance you wish to append

        Returns:
            An argument parser instance for the `MultipleResponsibilityInterface` derived class
        """
        actions_subparsers = parser.add_subparsers()
        for method, params_group in interface.interface_methods.items():
            if method in interface.supported_method_names:
                action_parser = actions_subparsers.add_parser(method.replace('_', '-'))
                action_parser.set_defaults(entry_method_name=method)
                for params in interface.base_params:
                    action_parser.add_argument(*params.flags, **params.kwargs)
                for params in params_group:
                    try:
                        action_parser.add_argument(*params.flags, **params.kwargs)
                    except argparse.ArgumentError:
                        continue
        return parser

    def get_parser(self) -> argparse.ArgumentParser:
        """Get the current interface as an `argparse.ArgumentParser` instance

        Returns:
             An argument parser instance for the `MultipleResponsibilityInterface` derived class
        """
        parser = argparse.ArgumentParser(description=f'{self.interface_name} - {self.interface_description}')
        return self.build_parser(self, parser)

    def execute(self, args: argparse.Namespace) -> Any:
        """Interpret the results of an `argparse.ArgumentParser.parse_args()` method and perform one or more operations.
        Args:
            args: The output of argparse.ArgumentParser.parse_args() function
        Returns:
            Any value; completely depends on the `selected_method` being invoked
        """
        constructor_kwargs = dict()
        entry_method_kwargs = dict()
        for param, value in vars(args).items():
            if param in [p.name for p in self.base_params]:
                constructor_kwargs[param] = value
            else:
                entry_method_kwargs[param] = value
        entry_method_kwargs.pop('component', None)
        entry_method_kwargs.pop('interface', None)
        entry_method_kwargs.pop('sub_interface', None)
        entry_method_kwargs.pop('entry_method_name', None)
        # Dynamically load our class
        klass = getattr(self, 'cls')
        # Instantiate it with the constructor kwargs
        exec_inst = klass(**constructor_kwargs)
        # Dynamically load our defined entry_method
        exec_entry_method = getattr(exec_inst, args.entry_method_name)
        # Call the entry method
        return exec_entry_method(**entry_method_kwargs)


class SingleResponsibilityInterface(BaseInterface):
    """
    Maps a class with only one responsibility to commandline interface
    For example InstallManager's only need call one function (perform one responsibility) once instantiated.

    SingleResponsibilityInterface:

    1. Takes a single class and entry_method_name.
    2. Uses several introspection techniques to enumerate instance methods from that class
    3. Derives the **kwargs params for argparse.ArgumentParser.add_arguments method for the __init__, and entry_method
    4. Generates parser using annotation and docs
    5. Provide a method for executing the parsed argparse.Namespace against
       cls.__init__(**base_kwargs).{entry_method(**interface_kwargs)}
    """

    def __init__(self, cls: object, entry_method_name: str, interface_name: str,
                 interface_description: Optional[str] = None, defaults: Optional[Dict] = None):
        """Initialize the interface
        Args:
            cls: The class we wish to turn into a commandline utility
            entry_method_name: The name of the method inside the above class we wish to call at execution time
            interface_name: The name of this commandline interface
            interface_description: A description of what this interface is supposed to do
            defaults: A dictionary where the key a parameter name and the value represents the value to default too.
        """

        super().__init__(interface_name, interface_description, defaults=defaults)
        self.cls = cls
        self.entry_method_name = entry_method_name
        self.defaults = defaults
        if not self.defaults:
            self.defaults = dict()
        if not interface_description:
            self.interface_description = inspect.getdoc(cls)
        self.base_params, self.interface_methods = get_class_instance_methods(cls, defaults, use_parent_init=False)
        self.interface_params = self.interface_methods[self.entry_method_name]

    @staticmethod
    def build_parser(interface: SingleResponsibilityInterface,
                     parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
        """Build a parser from any `SingleResponsibilityInterface` and `argparse.ArgumentParser` derived class
        Args:
            parser: The `argparse.ArgumentParser` instance that you want to add a new parser too
            interface: The `SingleResponsibilityInterface` instance you wish to append

        Returns:
            An argument parser instance for the `SingleResponsibilityInterface` derived class
        """
        for params in interface.base_params:
            parser.add_argument(*params.flags, **params.kwargs)
        for params in interface.interface_params:
            parser.add_argument(*params.flags, **params.kwargs)
        return parser

    def get_parser(self) -> argparse.ArgumentParser:
        """Get the current interface as an `argparse.ArgumentParser` instance

        Returns:
            An argument parser instance for the `SingleResponsibilityInterface` derived class
        """
        parser = argparse.ArgumentParser(description=f'{self.interface_name} - {self.interface_description}')
        return self.build_parser(self, parser)

    def execute(self, args: argparse.Namespace) -> Any:
        """Interpret the results of an `argparse.ArgumentParser.parse_args()` method and perform one or more operations.
        Args:
            args: The output of argparse.ArgumentParser.parse_args() function
        Returns:
            Any value; depending on the value returned from the `entry_method`
        """
        if getattr(args, 'background', None):
            setattr(args, 'background', None)
            return self.execute_in_background(args)

        constructor_kwargs = dict()
        entry_method_kwargs = dict()
        for param, value in vars(args).items():
            if param in [p.name for p in self.base_params]:
                constructor_kwargs[param] = value
            else:
                entry_method_kwargs[param] = value
        entry_method_kwargs.pop('component', None)
        entry_method_kwargs.pop('interface', None)
        entry_method_kwargs.pop('sub_interface', None)

        entry_method_kwargs.pop('background', None)
        # Dynamically load our class
        klass = getattr(self, 'cls')
        # Instantiate it with the constructor kwargs
        exec_inst = klass(**constructor_kwargs)
        # Dynamically load our defined entry_method
        exec_entry_method = getattr(exec_inst, self.entry_method_name)
        # Call the entry method
        return exec_entry_method(**entry_method_kwargs)

    def execute_in_background(self, args: argparse.Namespace) -> None:
        """Call execute, but run in the background inside a dedicated process.
        Args:
            args: The output of argparse.ArgumentParser.parse_args() function
        Returns:
            None
        """
        args.verbose = True
        args.stdout = False
        with daemon.DaemonContext():
            self.execute(args)


class SimpleConfigManagerInterface(SingleResponsibilityInterface):
    """
    Based upon the SingleResponsibilityInterface maps a class with only one responsibility to commandline interface,
    but also makes all the instance variables of the configuration class available as commandline arguments
    """

    def __init__(self, config: Union[config.GenericConfigManager, config.YamlConfigManager], interface_name: str,
                 interface_description: Optional[str] = None, pretty_print_status: Optional[bool] = True, defaults: Optional[Dict] = None):
        """Initialize the interface
        Args:
            config: The class we wish to turn into a commandline utility
            interface_name: The name of this commandline interface
            interface_description: A description of what this interface is supposed to do
            defaults: A dictionary where the key a parameter name and the value represents the value to default too.
        """
        self.config = config
        self.config_module_map = {}
        self.pretty_print_status = pretty_print_status
        super().__init__(self.config.__class__, 'commit', interface_name, interface_description, defaults)

    @staticmethod
    def build_parser(interface: SimpleConfigManagerInterface,
                     parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
        """Build a parser from any `SimpleConfigManagerInterface` and `argparse.ArgumentParser` derived class
        Args:
            parser: The `argparse.ArgumentParser` instance that you want to add a new parser too
            interface: The `SimpleConfigManagerInterface` instance you wish to append

        Returns:
            An argument parser instance for the `SimpleConfigManagerInterface` derived class
        """
        config_options = parser.add_argument_group('configuration options')
        config_objects_subparser = parser.add_subparsers()
        for params in interface.base_params + interface.interface_params:
            parser.add_argument(*params.flags, **params.kwargs)
        for var in vars(interface.config):
            if var in RESERVED_VARIABLE_NAMES:
                continue
            elif var.startswith('_'):
                continue
            elif '_raw' in var:
                continue
            elif var in [param.name for param in interface.base_params]:
                continue
            elif 'config_objects' in str(type(getattr(interface.config, var))):
                complex_obj = getattr(interface.config, var)
                if isinstance(complex_obj, Analyzers):
                    config_module_interface = AnalyzersInterface(complex_obj)
                    interface.config_module_map.update({var: config_module_interface})
                    interface_operations.append_service_interface_to_parser(config_objects_subparser,
                                                                            interface=config_module_interface,
                                                                            interface_name=var,
                                                                            interface_group_name='config_module')
                elif isinstance(complex_obj, targets.BaseTargets):
                    config_module_interface = FilebeatTargetsInterface(complex_obj)
                    interface.config_module_map.update({var: config_module_interface})
                    interface_operations.append_service_interface_to_parser(config_objects_subparser,
                                                                            interface=config_module_interface,
                                                                            interface_name=var,
                                                                            interface_group_name='config_module')
                elif isinstance(complex_obj, node.BaseComponent):
                    config_module_interface = ZeekNodeConfigObjectInterface(complex_obj)
                    interface.config_module_map.update({var: config_module_interface})
                    interface_operations.append_service_interface_to_parser(config_objects_subparser,
                                                                            interface=config_module_interface,
                                                                            interface_name=var,
                                                                            interface_group_name='config_module')
                elif isinstance(complex_obj, node.BaseComponents):
                    config_module_interface = ZeekNodeConfigObjectsInterface(complex_obj)
                    interface.config_module_map.update({var: config_module_interface})
                    interface_operations.append_service_interface_to_parser(config_objects_subparser,
                                                                            interface=config_module_interface,
                                                                            interface_name=var,
                                                                            interface_group_name='config_module')
                elif isinstance(complex_obj, misc.AfPacketInterfaces):
                    config_module_interface = SuricataInterfaceConfigObjectsInterface(complex_obj)
                    interface.config_module_map.update({var: config_module_interface})
                    interface_operations.append_service_interface_to_parser(config_objects_subparser,
                                                                            interface=config_module_interface,
                                                                            interface_name=var,
                                                                            interface_group_name='config_module')
            else:
                args = ArgparseParameters.create_from_typing_annotation(var, type(getattr(interface.config, var)),
                                                                        required=False)
                try:
                    config_options.add_argument(*args.flags, **args.kwargs)
                except argparse.ArgumentError:
                    continue
        return parser

    def get_parser(self) -> argparse.ArgumentParser:
        """Returns an argparse.ArgumentParser instance before parse_args has been called.

        Returns:
             argparse.ArgumentParser instance
        """
        parser = super().get_parser()
        return self.build_parser(self, parser)

    def execute(self, args: argparse.Namespace) -> Any:
        """Interpret the results of an `argparse.ArgumentParser.parse_args()` method and perform one or more operations.
        Args:
            args: The output of argparse.ArgumentParser.parse_args() function
        Returns:
            Any value; depending on the value returned from the `entry_method` (usually a `ConfigManager.commit`)
        """
        changed_config = False
        if not getattr(args, 'config_module', None):
            args.config_module = None
        headers = ['Config Option', 'Value']
        table = [headers]
        changed_rows_only = [headers]
        
        # In the scenario we have configuration modules include them as config options in our display table
        table.extend(
            [[config_module_name, 'Configuration Module'] for config_module_name in self.config_module_map.keys()])

        for option, value in args.__dict__.items():
            if option in self.defaults:
                continue
            if option in RESERVED_VARIABLE_NAMES:
                continue
            if not value:
                config_value = (option, getattr(self.config, option, None))
                table.append(config_value)
            else:
                changed_config = True
                changed_config_value = (option, value)
                changed_rows_only.append(changed_config_value)
                setattr(self.config, option, value)
        if args.config_module:
            # Configuration module interfaces need to pass through relevant commandline defaults from parent interface
            self.config_module_map[args.config_module].defaults = self.defaults

            selected_config_module = self.config_module_map[args.config_module]
            res = selected_config_module.execute(args)
            if isinstance(res, Analyzers):
                selected_analyzer_header = ['Id', 'Name', 'Enabled', 'Value']
                setattr(self.config, args.config_module, res)
                self.config.commit()
                return tabulate(selected_config_module.changed_rows, headers=selected_analyzer_header,
                                tablefmt='fancy_grid')
            elif isinstance(res, targets.BaseTargets):
                setattr(self.config, args.config_module, res)
                self.config.commit()
                return tabulate(selected_config_module.changed_rows, headers=headers, tablefmt='fancy_grid')
            elif isinstance(res, node.BaseComponent):
                setattr(self.config, args.config_module, res)
                self.config.commit()
                return tabulate(selected_config_module.changed_rows, headers=headers, tablefmt='fancy_grid')
            elif isinstance(res, node.BaseComponents):
                setattr(self.config, args.config_module, res)
                self.config.commit()
                return tabulate(selected_config_module.changed_rows, headers=headers, tablefmt='fancy_grid')
            elif isinstance(res, misc.AfPacketInterfaces):
                self.config.commit()
                return tabulate(selected_config_module.changed_rows, headers=headers, tablefmt='fancy_grid')
            else:
                return res
        else:
            if changed_config:
                self.config.commit()
                if self.pretty_print_status:
                    return tabulate(changed_rows_only, tablefmt='fancy_grid')
                return dict(changed_rows_only)
            else:
                if self.pretty_print_status:
                    return tabulate(table, tablefmt='fancy_grid')
                return dict(table)


def append_service_multiple_responsibility_interface_to_parser(
        parser: argparse.ArgumentParser, interface: MultipleResponsibilityInterface) -> argparse.ArgumentParser:
    """
    Append an `MultipleResponsibilityInterface` to an existing parser as a sub-parser.
    Args:
        parser: The parser to append our interface too
        interface: The new interface to add to the parser

    Returns:
        A new parser
    """
    return interface.build_parser(interface, parser)


def append_service_single_responsibility_interface_to_parser(parser: argparse.ArgumentParser,
                                                             interface: SingleResponsibilityInterface) -> \
        argparse.ArgumentParser:
    """
    Append an `SingleResponsibilityInterface` to an existing parser as a sub-parser.
    Args:
        parser: The parser to append our interface too
        interface: The new interface to add to the parser

    Returns:
        A new parser
    """
    return interface.build_parser(interface, parser)


def append_service_simple_config_management_interface_to_parser(parser: argparse.ArgumentParser,
                                                                interface: SimpleConfigManagerInterface) -> \
        argparse.ArgumentParser:
    """Append an `SimpleConfigManagerInterface` to an existing parser as a sub-parser.
    Args:
        parser: The parser to append our interface too
        interface: The new interface to add to the parser

    Returns:
        A new parser
    """
    return interface.build_parser(interface, parser)
