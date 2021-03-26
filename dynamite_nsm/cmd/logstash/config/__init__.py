import argparse
from dynamite_nsm.cmd.logstash.config import main, java
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Logstash Configuration Manager')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'main', main.interface, interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'java', java.interface, interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        main=main.interface,
        java=java.interface,
    )
