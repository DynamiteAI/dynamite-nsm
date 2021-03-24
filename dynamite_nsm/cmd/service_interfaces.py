import argparse
import inspect
from typing import Any, Dict, List, Optional, Union

from tabulate import tabulate

from dynamite_nsm.cmd.inspection_helpers import ArgparseParameters
from dynamite_nsm.cmd.inspection_helpers import get_class_instance_methods
from dynamite_nsm.services.base import config


class MultipleResponsibilityInterface:

    def __init__(self, cls: object, supported_method_names: List[str], interface_name: str,
                 interface_description: Optional[str] = None, defaults: Optional[Dict] = None):
        """
        :param cls: The class we wish to turn into a commandline utility
        :param supported_method_names: A list of methods to create interfaces for
        :param interface_name: The name of this commandline interface
        :param interface_description: A description of what this interface is supposed to do
        :param defaults: A dictionary where the key a parameter name and the value represents the value to default it too.
        """

        self.cls = cls
        self.supported_method_names = supported_method_names
        self.interface_name = interface_name
        self.interface_description = interface_description
        self.defaults = defaults
        if not interface_description:
            self.interfaceModuleType_description = inspect.getdoc(cls)
        self.base_params, self.interface_methods = get_class_instance_methods(cls, defaults, use_parent_init=False)

    def get_parser(self):
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


class SingleResponsibilityInterface:
    """
    Maps a class with only one responsibility to commandline interface
    For example InstallManager's only need call one function (perform one responsibility) once instantiated.

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
        :param defaults: A dictionary where the key a parameter name and the value represents the value to default it too.

        """
        self.cls = cls
        self.entry_method_name = entry_method_name
        self.interface_name = interface_name
        self.interface_description = interface_description
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
                               'out_file_path', 'backup_directory', 'top_text', 'interface', 'sub_interface']

    def __init__(self, config: Union[config.GenericConfigManager, config.YamlConfigManager], interface_name: str,
                 interface_description: Optional[str] = None, defaults: Optional[Dict] = None):
        self.config = config
        super().__init__(self.config.__class__, 'commit', interface_name, interface_description, defaults)

    def load_instance_variables_parser(self, config_obj: Union[config.GenericConfigManager, config.YamlConfigManager],
                                       parser: argparse.ArgumentParser, config_options):
        for var in vars(config_obj):
            if var in self.reserved_variable_names:
                continue
            elif '_raw' in var:
                continue
            elif var in [param.name for param in self.base_params]:
                continue
            elif 'config_objects' in str(type(getattr(config_obj, var))):
                complex_obj = getattr(config_obj, var)
                complex_config_options = parser.add_argument_group(var.capitalize())
            else:
                args = ArgparseParameters.create_from_typing_annotation(var, type(getattr(config_obj, var)))
                try:
                    config_options.add_argument(*args.flags, **args.kwargs)
                except argparse.ArgumentError:
                    continue
        return parser

    def get_parser(self) -> argparse.ArgumentParser:
        parser = super().get_parser()
        config_options = parser.add_argument_group('configuration options')
        return self.load_instance_variables_parser(self.config, parser, config_options)

    def execute(self, args: argparse.Namespace) -> Any:
        print(args)
        changed_config = False
        table = [['Config Option', 'Value']]
        changed_rows_only = [['Config Option', 'Value']]
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
        if changed_config:
            self.config.commit()
            return tabulate(changed_rows_only, tablefmt='fancy_grid')
        else:
            return tabulate(table, tablefmt='fancy_grid')


def append_service_interface_to_parser(parent_parser: argparse, interface_name: str,
                                       interface: Union[SingleResponsibilityInterface, MultipleResponsibilityInterface],
                                       interface_group_name: Optional[str] = 'interface') -> argparse.ArgumentParser:
    """
    Add an interface to an existing parser.

    :param parent_parser: The parent parser to add the interface too
    :param interface_name: The name of this interface as it will appear in the commandline utility
    :param interface: The interface object itself
    :param interface_group_name: A name identifying where in the component, interface, sub-interface hierarchy this
                                 service_interface should be placed
    :return: The parser object
    """
    if not interface:
        return
    interface_group_name_kwargs = {interface_group_name: interface_name}
    sub_interface_parser = parent_parser.add_parser(interface_name, help=interface.interface_description)
    sub_interface_parser.set_defaults(**interface_group_name_kwargs)

    def append_single_responsibility_interface(interface: SingleResponsibilityInterface):
        for params in interface.base_params + interface.interface_params:
            sub_interface_parser.add_argument(*params.flags, **params.kwargs)

    def append_multiple_responsibility_interface(interface: MultipleResponsibilityInterface):
        actions = []
        for params in interface.base_params:
            sub_interface_parser.add_argument(*params.flags, **params.kwargs)
        for method, params_group in interface.interface_methods.items():
            if method in interface.supported_method_names:
                if not params_group:
                    actions.append(method.replace('_', '-'))
                else:
                    for params in params_group:
                        sub_interface_parser.add_argument(*params.flags, **params.kwargs)
        if actions:
            sub_interface_parser.add_argument('action', choices=actions)

    def append_simple_config_management_interface(interface: SimpleConfigManagerInterface):
        config_options = sub_interface_parser.add_argument_group('configuration options')
        for params in interface.base_params + interface.interface_params:
            sub_interface_parser.add_argument(*params.flags, **params.kwargs)
        for var in vars(interface.config):
            if var in interface.reserved_variable_names:
                continue
            elif '_raw' in var:
                continue
            elif var in [param.name for param in interface.base_params]:
                continue
            args = ArgparseParameters.create_from_typing_annotation(var, type(getattr(interface.config, var)),
                                                                    required=False)
            config_options.add_argument(*args.flags, **args.kwargs)

    if isinstance(interface, SimpleConfigManagerInterface):
        append_simple_config_management_interface(interface)
    elif isinstance(interface, SingleResponsibilityInterface):
        append_single_responsibility_interface(interface)
    elif isinstance(interface, MultipleResponsibilityInterface):
        append_multiple_responsibility_interface(interface)


def append_service_interfaces_to_parser(
        parent_parser: argparse,interfaces: Dict[str,
                                                 Union[SingleResponsibilityInterface, MultipleResponsibilityInterface]],
        interface_group_name: Optional[str] = 'sub_interface') -> argparse.ArgumentParser:
    """
    Append multiple service interfaces to a single parser

    :param parent_parser:
    :param interfaces: A dictionary service interface objects where the key is the name of that interface,
                    and the value is the interface object itself.
    :param interface_group_name: A name identifying where in the component, interface, sub-interface hierarchy these
                                 service_interfaces should be placed
    :return: The parser object
    """

    for name, value in interfaces.items():
        if isinstance(value, tuple):
            interfaces, help_str = value
            new_section_parser = parent_parser.add_parser(name=name, help=help_str)
            new_section_subparsers = new_section_parser.add_subparsers()
            append_service_interfaces_to_parser(parent_parser=new_section_subparsers, interfaces=interfaces,
                                                interface_group_name=interface_group_name)
        elif isinstance(value, dict):
            new_section_parser = parent_parser.add_parser(name=name, help='<None Given>')
            new_section_subparsers = new_section_parser.add_subparsers()
            append_service_interfaces_to_parser(parent_parser=new_section_subparsers, interfaces=value,
                                                interface_group_name=interface_group_name)
        else:
            append_service_interface_to_parser(parent_parser=parent_parser, interface_name=name, interface=value,
                                               interface_group_name=interface_group_name)
    return parent_parser
