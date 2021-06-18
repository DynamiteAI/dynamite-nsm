import argparse
from dynamite_nsm.cmd.elasticsearch.config import main, java, users
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Elasticsearch Config Manager')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'main', main.interface, interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'users', users.interface, interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'java', java.interface, interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        main=main.interface,
        users=users.interface,
        java=java.interface,
    )
