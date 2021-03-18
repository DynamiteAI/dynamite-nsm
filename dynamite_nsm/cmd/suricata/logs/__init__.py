import argparse

from dynamite_nsm.cmd.suricata.logs import main, metrics
from dynamite_nsm.service_to_commandline import append_interface_to_parser
from dynamite_nsm.utilities import get_primary_ip_address


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Suricata @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_interface_to_parser(subparsers, 'main', main.interface, interface_group_name='sub_interface')
    append_interface_to_parser(subparsers, 'metrics', metrics.interface, interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        main=main.interface,
        metrics=metrics.interface,
    )
