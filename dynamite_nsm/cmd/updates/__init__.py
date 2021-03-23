import argparse

from dynamite_nsm.cmd.updates import install
from dynamite_nsm.service_to_commandline import append_interface_to_parser, append_interfaces_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Update default configurations and mirrors.')
    subparsers = parser.add_subparsers()
    append_interface_to_parser(subparsers, 'install', install.interface, interface_group_name='interface')
    return parser


def get_interfaces():
    return dict(
        install=install.interface
    )
