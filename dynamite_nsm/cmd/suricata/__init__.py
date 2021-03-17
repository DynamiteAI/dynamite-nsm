import argparse

from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.cmd.suricata import logs, install, process, uninstall
from dynamite_nsm.service_to_commandline import append_interface_to_parser
from dynamite_nsm.cmd.suricata.logs import get_interfaces as get_logs_interfaces


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Suricata @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()

    append_interface_to_parser(subparsers, 'install', install.interface)
    append_interface_to_parser(subparsers, 'uninstall', uninstall.interface)
    append_interface_to_parser(subparsers, 'process', process.interface)
    log_parser = subparsers.add_parser('logs', help='Attach to various Suricata logs.')
    log_parser.set_defaults(sub_interface='logs')
    log_sub_parsers = log_parser.add_subparsers()
    for interface_name, interface in get_logs_interfaces().items():
        append_interface_to_parser(log_sub_parsers, interface_name, interface)
    return parser


def get_interfaces():
    return dict(
        install=install.interface,
        uninstall=uninstall.interface,
        process=process.interface,
        logs=get_logs_interfaces()
    )