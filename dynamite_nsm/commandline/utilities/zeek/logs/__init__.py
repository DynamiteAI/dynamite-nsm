import argparse
from dynamite_nsm.utilities import get_primary_ip_address
from dynamite_nsm.commandline.service_to_commandline import append_interface_to_parser
from dynamite_nsm.commandline.utilities.zeek.logs import broker, cluster, metrics, reporter


def get_action_parser():
    parser = argparse.ArgumentParser(description=f'Zeek @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()
    append_interface_to_parser(subparsers, 'broker', broker.interface)
    append_interface_to_parser(subparsers, 'cluster', cluster.interface)
    append_interface_to_parser(subparsers, 'metrics', metrics.interface)
    append_interface_to_parser(subparsers, 'reporter', reporter.interface)
    return parser


def get_interfaces():
    return dict(
        broker=broker.interface,
        cluster=cluster.interface,
        metrics=metrics.interface,
        reporter=reporter.interface
    )
