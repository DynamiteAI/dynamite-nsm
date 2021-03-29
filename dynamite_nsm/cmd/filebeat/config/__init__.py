import argparse

from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser
from dynamite_nsm.cmd.filebeat.config import main


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Filebeat Configuration Manager')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'main', main.interface,
                                       interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        main=main.interface
    )
