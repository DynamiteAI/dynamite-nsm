import argparse

from dynamite_nsm.cmd.elasticsearch import install, process, uninstall
from dynamite_nsm.cmd.elasticsearch.config import get_interfaces as get_config_interfaces
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser, \
    append_service_interfaces_to_parser
from dynamite_nsm.utilities import get_primary_ip_address

ES_CONFIG_HELP = 'Modify Elasticsearch configurations.'


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Elasticsearch @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'install', interface=install.interface,
                                       interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'uninstall', interface=uninstall.interface,
                                       interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'process', interface=process.interface,
                                       interface_group_name='interface')
    config_parser = subparsers.add_parser('config', help=ES_CONFIG_HELP)
    config_parser.set_defaults(interface='config')
    config_sub_parsers = config_parser.add_subparsers()
    append_service_interfaces_to_parser(config_sub_parsers, interfaces=get_config_interfaces(),
                                        interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        install=install.interface,
        uninstall=uninstall.interface,
        process=process.interface,
        config=(get_config_interfaces(), ES_CONFIG_HELP)
    )
