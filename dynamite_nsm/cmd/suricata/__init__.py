import argparse

from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser, \
    append_service_interfaces_to_parser
from dynamite_nsm.cmd.suricata import logs, install, process, uninstall, update, reset
from dynamite_nsm.cmd.suricata.logs import get_interfaces as get_logs_interfaces
from dynamite_nsm.cmd.suricata.config import get_interfaces as get_config_interfaces
from dynamite_nsm.utilities import get_primary_ip_address

SURICATA_CONFIG_HELP = 'Modify Suricata configurations.'
SURICATA_LOGS_HELP = 'Attach to various Suricata logs.'


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Suricata @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()

    append_service_interface_to_parser(subparsers, 'install', install.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'uninstall', uninstall.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'update', update.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'process', process.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'reset', reset.interface, interface_group_name='interface')
    config_parser = subparsers.add_parser('config', help=SURICATA_CONFIG_HELP)
    config_parser.set_defaults(interface='config')
    config_sub_parsers = config_parser.add_subparsers()
    append_service_interfaces_to_parser(config_sub_parsers, interfaces=get_config_interfaces(),
                                        interface_group_name='sub_interface')
    log_parser = subparsers.add_parser('logs', help=SURICATA_LOGS_HELP)
    log_parser.set_defaults(interface='logs')
    log_sub_parsers = log_parser.add_subparsers()
    append_service_interfaces_to_parser(log_sub_parsers, interfaces=get_logs_interfaces(),
                                        interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        install=install.interface,
        uninstall=uninstall.interface,
        process=process.interface,
        logs=get_logs_interfaces()
    )
