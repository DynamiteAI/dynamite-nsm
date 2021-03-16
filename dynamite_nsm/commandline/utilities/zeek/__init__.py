import argparse
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.commandline.service_to_commandline import append_interface_to_parser
from dynamite_nsm.commandline.utilities.zeek import install, process, logs
from dynamite_nsm.commandline.utilities.zeek.logs import get_interfaces


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Zeek @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()

    append_interface_to_parser(subparsers, 'install', install.interface)
    append_interface_to_parser(subparsers, 'process', process.interface)
    log_parser = subparsers.add_parser('logs', help='Attach to various Zeek logs.')
    log_sub_parsers = log_parser.add_subparsers()
    for interface_name, interface in get_interfaces().items():
        append_interface_to_parser(log_sub_parsers, interface_name, interface)
    return parser

