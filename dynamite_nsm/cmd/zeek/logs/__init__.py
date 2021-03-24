import argparse
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.cmd.interface_operations import append_service_interface_to_parser
from dynamite_nsm.cmd.zeek.logs import cluster, broker, metrics, reporter


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Zeek @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_service_interface_to_parser(subparsers, 'broker', broker.interface, interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'cluster', cluster.interface, interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'metrics', metrics.interface, interface_group_name='sub_interface')
    append_service_interface_to_parser(subparsers, 'reporter', reporter.interface, interface_group_name='sub_interface')
    return parser


def get_interfaces():
    return dict(
        broker=broker.interface,
        cluster=cluster.interface,
        metrics=metrics.interface,
        reporter=reporter.interface
    )
