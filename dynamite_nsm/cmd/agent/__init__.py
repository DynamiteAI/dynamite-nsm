import argparse

from dynamite_nsm.cmd.agent import install, uninstall
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Install agent components')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'install', install.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'uninstall', uninstall.interface, interface_group_name='interface')
    return parser


def get_interfaces():
    return dict(
        install=install.interface
    )
