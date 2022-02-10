import argparse
from typing import Dict, Optional

from dynamite_nsm.cmd.base_interface import BaseInterface


def append_service_interface_to_parser(parent_parser: argparse, interface_name: str, interface: BaseInterface,
                                       interface_group_name: Optional[str] = 'interface') -> argparse.ArgumentParser:
    """Add an interface to an existing parser.
    Args:
        parent_parser: The parent parser to add the interface too
        interface_name: The name of this interface as it will appear in the commandline utility
        interface: The interface object itself
        interface_group_name: A name identifying where in the component, interface, sub-interface hierarchy this
        service_interface should be placed
    Returns:
         The parser object
    """
    from dynamite_nsm.cmd import service_interfaces
    from dynamite_nsm.cmd import config_object_interfaces
    from dynamite_nsm.cmd.config_object_interfaces import AnalyzersInterface, FilebeatTargetsInterface, \
        SuricataInterfaceConfigObjectsInterface, ZeekNodeConfigObjectInterface, ZeekNodeConfigObjectsInterface
    from dynamite_nsm.cmd.service_interfaces import MultipleResponsibilityInterface, SingleResponsibilityInterface, \
        SimpleConfigManagerInterface

    if not interface:
        return argparse.ArgumentParser()
    interface_group_name_kwargs = {interface_group_name: interface_name}
    sub_interface_parser = parent_parser.add_parser(interface_name, help=interface.interface_description)
    sub_interface_parser.set_defaults(**interface_group_name_kwargs)

    if isinstance(interface, SimpleConfigManagerInterface):
        service_interfaces.append_service_simple_config_management_interface_to_parser(parser=sub_interface_parser,
                                                                                       interface=interface)
    elif isinstance(interface, SingleResponsibilityInterface):
        service_interfaces.append_service_single_responsibility_interface_to_parser(parser=sub_interface_parser,
                                                                                    interface=interface)
    elif isinstance(interface, MultipleResponsibilityInterface):
        service_interfaces.append_service_multiple_responsibility_interface_to_parser(parser=sub_interface_parser,
                                                                                      interface=interface)
    elif isinstance(interface, AnalyzersInterface):
        config_object_interfaces.append_config_object_analyzer_interface_to_parser(parser=sub_interface_parser,
                                                                                   interface=interface)
    elif isinstance(interface, FilebeatTargetsInterface):
        config_object_interfaces.append_config_object_filebeat_targets_to_parser(parser=sub_interface_parser,
                                                                                 interface=interface)
    elif isinstance(interface, SuricataInterfaceConfigObjectsInterface):
        config_object_interfaces.append_config_object_suricata_interface_obj_to_parser(parser=sub_interface_parser,
                                                                                       interface=interface)
    elif isinstance(interface, ZeekNodeConfigObjectInterface):
        config_object_interfaces.append_config_object_zeek_node_obj_to_parser(parser=sub_interface_parser,
                                                                              interface=interface)
    elif isinstance(interface, ZeekNodeConfigObjectsInterface):
        config_object_interfaces.append_config_object_zeek_node_objs_to_parser(parser=sub_interface_parser,
                                                                               interface=interface)
    return parent_parser


def append_service_interfaces_to_parser(
        parent_parser: argparse, interfaces: Dict[str, BaseInterface],
        interface_group_name: Optional[str] = 'sub_interface') -> argparse.ArgumentParser:
    """Append multiple service interfaces to a single parser
    Args:
        parent_parser:
        interfaces: A dictionary service interface packages where the key is the name of that interface, and the value
        is the interface object itself.
        interface_group_name: A name identifying where in the component, interface, sub-interface hierarchy these
        service_interfaces should be placed
    Returns:
         The parser object
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
