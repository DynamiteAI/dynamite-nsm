import argparse
import inspect
from typing import Any, Dict, List, Optional, Union

from tabulate import tabulate

from dynamite_nsm.cmd import interface_operations
from dynamite_nsm.cmd.base_interface import BaseInterface
from dynamite_nsm.cmd.config_object_interfaces import AnalyzersInterface
from dynamite_nsm.cmd.inspection_helpers import ArgparseParameters
from dynamite_nsm.cmd.inspection_helpers import get_class_instance_methods
from dynamite_nsm.services.base import config
from dynamite_nsm.services.base.config_objects.generic import Analyzers

"""
Commandline interface wrappers for services
"""


class MultipleResponsibilityInterface(BaseInterface):
    """
    Maps a class with several responsibilities to commandline interface
    For example ProcessManager's provides multiple methods that can be invoked to perform various tasks:
    - start
    - stop
    - restart
    - status

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
        """
        :param cls: The class we wish to turn into a commandline utility
        :param supported_method_names: A list of methods to create interfaces for
        :param interface_name: The name of this commandline interface
        :param interface_description: A description of what this interface is supposed to do
        :param defaults: A dictionary where the key a parameter name and the value represents the value to default too.
        """

        super().__init__(interface_name, interface_description)
        self.cls = cls
        self.supported_method_names = supported_method_names
        self.defaults = defaults
        if not interface_description:
            self.interfaceModuleType_description = inspect.getdoc(cls)
        self.base_params, self.interface_methods = get_class_instance_methods(cls, defaults, use_parent_init=False)

    def get_parser(self) -> argparse.ArgumentParser:
        """
        Returns an argparse.ArgumentParser instance before parse_args has been called.

        :return: argparse.ArgumentParser instance
        """
        actions = []
        parser = argparse.ArgumentParser(description=f'{self.interface_name} - {self.interface_description}')
        for params in self.base_params:
            parser.add_argument(*params.flags, **params.kwargs)
        for method, params_group in self.interface_methods.items():
            if method in self.supported_method_names:
                if not params_group:
                    actions.append(method.replace('_', '-'))
                else:
                    for params in params_group:
                        parser.add_argument(*params.flags, **params.kwargs)
        if actions:
            parser.add_argument('action', choices=actions)
        return parser

    def execute(self, args: argparse.Namespace) -> Any:
        """
        Given a set of parsed arguments execute those arguments according the defined parameters and entry_method_name

        **Note the args.Namespace must contain an "action" parameter in order to function properly

        :param args: The output of argparse.ArgumentParser.parse_args() function
        """
        constructor_kwargs = dict()
        entry_method_kwargs = dict()
        for param, value in vars(args).items():
            if param == 'action':
                continue
            if param in [p.name for p in self.base_params]:
                constructor_kwargs[param] = value
            else:
                entry_method_kwargs[param] = value

        # Dynamically load our class
        klass = getattr(self, 'cls')
        # Instantiate it with the constructor kwargs
        exec_inst = klass(**constructor_kwargs)
        # Dynamically load our defined entry_method
        exec_method = getattr(exec_inst, args.action.replace('-', '_'))
        entry_method_kwargs.pop('component', None)
        entry_method_kwargs.pop('interface', None)
        entry_method_kwargs.pop('sub_interface', None)
        # Call the entry method
        return exec_method(**entry_method_kwargs)


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
        """
        :param cls: The class we wish to turn into a commandline utility
        :param entry_method_name: The name of the method inside the above class we wish to call at execution time
        :param interface_name: The name of this commandline interface
        :param interface_description: A description of what this interface is supposed to do
        :param defaults: A dictionary where the key a parameter name and the value represents the value to default too.
        """

        super().__init__(interface_name, interface_description)
        self.cls = cls
        self.entry_method_name = entry_method_name
        self.defaults = defaults
        if not interface_description:
            self.interface_description = inspect.getdoc(cls)
        self.base_params, self.interface_methods = get_class_instance_methods(cls, defaults, use_parent_init=False)
        self.interface_params = self.interface_methods[self.entry_method_name]

    def get_parser(self) -> argparse.ArgumentParser:
        """
        Returns an argparse.ArgumentParser instance before parse_args has been called.

        :return: argparse.ArgumentParser instance
        """
        parser = argparse.ArgumentParser(description=f'{self.interface_name} - {self.interface_description}')
        for params in self.base_params:
            parser.add_argument(*params.flags, **params.kwargs)

        for params in self.interface_params:
            parser.add_argument(*params.flags, **params.kwargs)
        return parser

    def execute(self, args: argparse.Namespace) -> Any:
        """
        Given a set of parsed arguments execute those arguments according the defined parameters and entry_method_name

        :param args: The output of argparse.ArgumentParser.parse_args() function
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
        # Dynamically load our class
        klass = getattr(self, 'cls')
        # Instantiate it with the constructor kwargs
        exec_inst = klass(**constructor_kwargs)
        # Dynamically load our defined entry_method
        exec_entry_method = getattr(exec_inst, self.entry_method_name)
        # Call the entry method
        return exec_entry_method(**entry_method_kwargs)


class SimpleConfigManagerInterface(SingleResponsibilityInterface):
    """
    Based upon the SingleResponsibilityInterface maps a class with only one responsibility to commandline interface,
    but also makes all the instance variables of the configuration class available as commandline arguments
    """
    reserved_variable_names = ['config_data', 'extract_tokens', 'formatted_data', 'stdout', 'verbose', 'logger',
                               'out_file_path', 'backup_directory', 'top_text', 'interface', 'sub_interface',
                               'config_module']

    def __init__(self, config: Union[config.GenericConfigManager, config.YamlConfigManager], interface_name: str,
                 interface_description: Optional[str] = None, defaults: Optional[Dict] = None):
        """
        :param config: The class we wish to turn into a commandline utility
        :param interface_name: The name of this commandline interface
        :param interface_description: A description of what this interface is supposed to do
        :param defaults: A dictionary where the key a parameter name and the value represents the value to default too.
        """
        self.config = config
        self.config_module_map = {}
        super().__init__(self.config.__class__, 'commit', interface_name, interface_description, defaults)

    def get_parser(self) -> argparse.ArgumentParser:
        parser = super().get_parser()
        config_options = parser.add_argument_group('configuration options')
        config_objects_subparser = parser.add_subparsers()
        for var in vars(self.config):
            if var in self.reserved_variable_names:
                continue
            elif '_raw' in var:
                continue
            elif var in [param.name for param in self.base_params]:
                continue
            elif 'config_objects' in str(type(getattr(self.config, var))):
                complex_obj = getattr(self.config, var)
                if isinstance(complex_obj, Analyzers):
                    config_module_interface = AnalyzersInterface(complex_obj)
                    self.config_module_map.update({var: config_module_interface})
                    interface_operations.append_service_interface_to_parser(config_objects_subparser,
                                                                            interface=AnalyzersInterface(complex_obj),
                                                                            interface_name=var,
                                                                            interface_group_name='config_module')
            else:
                args = ArgparseParameters.create_from_typing_annotation(var, type(getattr(self.config, var)))
                try:
                    config_options.add_argument(*args.flags, **args.kwargs)
                except argparse.ArgumentError:
                    continue
        return parser

    def execute(self, args: argparse.Namespace) -> Any:
        """
        Given a set of parsed arguments execute those arguments using services.base.BaseConfigManager.commit()

        Also handles config_module interfaces (interfaces compatible with services.base.config_objects's)

        :param args: The output of argparse.ArgumentParser.parse_args() function
        """
        changed_config = False
        if not getattr(args, 'config_module', None):
            args.config_module = None
        table = [['Config Option', 'Value']]
        changed_rows_only = [['Config Option', 'Value']]

        # In the scenario we have configuration modules include them as config options in our display table
        table.extend(
            [[config_module_name, 'Configuration Module'] for config_module_name in self.config_module_map.keys()])

        for option, value in args.__dict__.items():
            if option in self.defaults:
                continue
            if option in self.reserved_variable_names:
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
            selected_config_module = self.config_module_map[args.config_module]
            res = selected_config_module.execute(args)
            if isinstance(res, Analyzers):
                setattr(self.config, args.config_module, res)
                self.config.commit()
            else:
                return res
        else:
            if changed_config:
                self.config.commit()
                return tabulate(changed_rows_only, tablefmt='fancy_grid')
            else:
                return tabulate(table, tablefmt='fancy_grid')


def append_service_multiple_responsibility_interface_to_parser(parser: argparse.ArgumentParser,
                                                               interface: MultipleResponsibilityInterface):
    actions = []
    for params in interface.base_params:
        parser.add_argument(*params.flags, **params.kwargs)
    for method, params_group in interface.interface_methods.items():
        if method in interface.supported_method_names:
            if not params_group:
                actions.append(method.replace('_', '-'))
            else:
                for params in params_group:
                    parser.add_argument(*params.flags, **params.kwargs)
    if actions:
        parser.add_argument('action', choices=actions)
    return parser


def append_service_single_responsibility_interface_to_parser(parser: argparse.ArgumentParser,
                                                             interface: SingleResponsibilityInterface):
    for params in interface.base_params + interface.interface_params:
        parser.add_argument(*params.flags, **params.kwargs)
    return parser


def append_service_simple_config_management_interface_to_parser(parser: argparse.ArgumentParser,
                                                                interface: SimpleConfigManagerInterface):
    config_options = parser.add_argument_group('configuration options')
    config_objects_subparser = parser.add_subparsers()
    for params in interface.base_params + interface.interface_params:
        parser.add_argument(*params.flags, **params.kwargs)
    for var in vars(interface.config):
        if var in interface.reserved_variable_names:
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
                                                                        interface=AnalyzersInterface(complex_obj),
                                                                        interface_name=var,
                                                                        interface_group_name='config_module')
        else:
            args = ArgparseParameters.create_from_typing_annotation(var, type(getattr(interface.config, var)))
            try:
                config_options.add_argument(*args.flags, **args.kwargs)
            except argparse.ArgumentError:
                continue
    return parser
