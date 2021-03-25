import argparse
from dynamite_nsm.cmd.zeek.config import site
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Zeek Configuration Manager')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'site', site.interface, interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        site=site.interface
    )
