import argparse

from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser, \
    append_service_interfaces_to_parser
from dynamite_nsm.cmd.kibana import install, package, process, uninstall
from dynamite_nsm.cmd.kibana.config import get_interfaces as get_config_interfaces
from dynamite_nsm.utilities import get_primary_ip_address

KIBANA_CONFIG_HELP = 'Modify Kibana configurations.'

def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Kibana @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'install', install.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'uninstall', uninstall.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'process', process.interface, interface_group_name='interface')
    config_parser = subparsers.add_parser('config', help=KIBANA_CONFIG_HELP)
    config_parser.set_defaults(interface='config')
    config_sub_parsers = config_parser.add_subparsers()
    append_service_interfaces_to_parser(config_sub_parsers, interfaces=get_config_interfaces(),
                                        interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'package', package.interface, interface_group_name='interface')
    return parser


def get_interfaces():
    return dict(
        install=install.interface,
        uninstall=uninstall.interface,
        process=process.interface,
        config=(get_config_interfaces(), KIBANA_CONFIG_HELP)
    )
