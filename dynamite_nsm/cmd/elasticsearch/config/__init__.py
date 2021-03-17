import argparse
from dynamite_nsm.cmd.elasticsearch.config import main, java
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.service_to_commandline import append_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Elasticsearch @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_interface_to_parser(subparsers, 'main', main.interface)
    append_interface_to_parser(subparsers, 'java', java.interface)
    return parser


def get_interfaces():
    return dict(
        main=main.interface,
        java=java.interface,
    )
