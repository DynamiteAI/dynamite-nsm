import argparse
from dynamite_nsm import utilities
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser
from dynamite_nsm.cmd.remote import install, uninstall
from dynamite_nsm.utilities import get_primary_ip_address


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Dynamite Remote Manager @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()

    append_service_interface_to_parser(subparsers, 'install', install.interface, interface_group_name='interface')
    append_service_interface_to_parser(subparsers, 'uninstall', uninstall.interface, interface_group_name='interface')
    return parser


def get_interfaces():
    print(utilities.PrintDecorations.colorize('This utility is in alpha and may change dramatically between releases!',
                                              _color='yellow'))
    return dict(
        install=install.interface,
        uninstall=uninstall.interface,
    )
