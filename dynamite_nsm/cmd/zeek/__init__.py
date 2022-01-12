import argparse

from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser, \
    append_service_interfaces_to_parser
from dynamite_nsm.cmd.zeek import install, process, uninstall, config, reset
from dynamite_nsm.cmd.zeek.reset import get_interfaces as get_reset_interfaces
from dynamite_nsm.cmd.zeek.logs import get_interfaces as get_logs_interfaces
from dynamite_nsm.cmd.zeek.config import get_interfaces as get_config_interfaces
from dynamite_nsm.utilities import get_primary_ip_address

ZEEK_RESET_HELP = 'Reset Zeek configurations to install state.'
ZEEK_CONFIG_HELP = 'Modify Zeek configurations.'
ZEEK_LOGS_HELP = 'Attach to various Zeek logs.'


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Zeek @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()

    append_service_interface_to_parser(subparsers, 'install', install.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'uninstall', uninstall.interface, interface_group_name='interface')

    append_service_interface_to_parser(subparsers, 'process', process.interface, interface_group_name='interface')

    reset_parser = subparsers.add_parser('reset', help=ZEEK_RESET_HELP)
    reset_parser.set_defaults(interface='reset')
    reset_sub_parsers = reset_parser.add_subparsers()
    append_service_interfaces_to_parser(reset_sub_parsers, interfaces=get_reset_interfaces())

    config_parser = subparsers.add_parser('config', help=ZEEK_CONFIG_HELP)
    config_parser.set_defaults(interface='config')
    config_sub_parsers = config_parser.add_subparsers()
    append_service_interfaces_to_parser(config_sub_parsers, interfaces=get_config_interfaces(),
                                        interface_group_name='sub_interface')

    log_parser = subparsers.add_parser('logs', help=ZEEK_LOGS_HELP)
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
