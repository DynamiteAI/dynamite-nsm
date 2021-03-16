import argparse
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.commandline.service_to_commandline import append_interface_to_parser
from dynamite_nsm.commandline.utilities.filebeat.logs import main, metrics


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Filebeat @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_interface_to_parser(subparsers, 'main', main.interface)
    append_interface_to_parser(subparsers, 'metrics', metrics.interface)
    return parser


def get_interfaces():
    return dict(
        main=main.interface,
        metrics=metrics.interface,
    )
