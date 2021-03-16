import argparse
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.cmd.elasticsearch import install, process, uninstall
from dynamite_nsm.service_to_commandline import append_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Elasticsearch @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_interface_to_parser(subparsers, 'install', install.interface)
    append_interface_to_parser(subparsers, 'uninstall', uninstall.interface)
    append_interface_to_parser(subparsers, 'process', process.interface)
    return parser

