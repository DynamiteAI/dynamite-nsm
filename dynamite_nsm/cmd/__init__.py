import argparse
from typing import Optional

from dynamite_nsm import service_to_commandline
from dynamite_nsm.cmd import elasticsearch, logstash, kibana, zeek, suricata, filebeat
from dynamite_nsm.utilities import get_primary_ip_address


def process_arguments(args: argparse.Namespace, component: Optional[str], interface: Optional[str] = None,
                      sub_interface: Optional[str] = None):
    component_modules = dict(
        elasticsearch=elasticsearch,
        logstash=logstash,
        kibana=kibana,
        zeek=zeek,
        suricata=suricata,
        filebeat=filebeat
    )

    try:
        component_interface = getattr(component_modules[component], interface)
        if sub_interface:
            component_interface = getattr(component_interface, sub_interface)
    except KeyError:
        raise ModuleNotFoundError(f'{component} is not a valid component module.')
    except AttributeError:
        raise ModuleNotFoundError(f'{component}.{interface} is not a valid interface module.')
    return component_interface.interface.execute(args)


def get_dynamite_parser():
    parser = argparse.ArgumentParser(description=f'Dynamite @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()

    elasticsearch_interfaces = elasticsearch.get_interfaces()
    elasticsearch_parser = subparsers.add_parser(name='elasticsearch',
                                                 help='Elasticsearch to store and search events.')
    elasticsearch_parser.set_defaults(component='elasticsearch')
    elasticsearch_subparsers = elasticsearch_parser.add_subparsers()

    logstash_interfaces = logstash.get_interfaces()
    logstash_parser = subparsers.add_parser(name='logstash', help='Logstash for brokering and enriching events.')
    logstash_parser.set_defaults(component='logstash')
    logstash_subparsers = logstash_parser.add_subparsers()

    kibana_interfaces = kibana.get_interfaces()
    kibana_parser = subparsers.add_parser(name='kibana', help='Kibana for visualizing and exploring your data.')
    kibana_parser.set_defaults(component='kibana')
    kibana_subparsers = kibana_parser.add_subparsers()

    zeek_interfaces = zeek.get_interfaces()
    zeek_parser = subparsers.add_parser(name='zeek',
                                        help='Zeek for extracting network metadata and finding cool '
                                             'patterns in our traffic.')

    zeek_parser.set_defaults(component='zeek')
    zeek_subparsers = zeek_parser.add_subparsers()
    suricata_interfaces = suricata.get_interfaces()
    suricata_parser = subparsers.add_parser(name='suricata', help='Suricata for finding evil and alerting upon it.')
    suricata_parser.set_defaults(component='suricata')
    suricata_subparsers = suricata_parser.add_subparsers()

    filebeat_interfaces = filebeat.get_interfaces()
    filebeat_parser = subparsers.add_parser(name='filebeat',
                                            help='Filebeat for sending events and alerts to the collector of '
                                                 'your choice.')
    filebeat_parser.set_defaults(component='filebeat')
    filebeat_subparsers = filebeat_parser.add_subparsers()

    service_to_commandline.append_interfaces_to_parser(elasticsearch_subparsers, interfaces=elasticsearch_interfaces,
                                                       interface_group_name='interface')
    service_to_commandline.append_interfaces_to_parser(logstash_subparsers, interfaces=logstash_interfaces,
                                                       interface_group_name='interface')
    service_to_commandline.append_interfaces_to_parser(kibana_subparsers, interfaces=kibana_interfaces,
                                                       interface_group_name='interface')
    service_to_commandline.append_interfaces_to_parser(zeek_subparsers, interfaces=zeek_interfaces,
                                                       interface_group_name='interface')
    service_to_commandline.append_interfaces_to_parser(suricata_subparsers, interfaces=suricata_interfaces,
                                                       interface_group_name='interface')
    service_to_commandline.append_interfaces_to_parser(filebeat_subparsers, interfaces=filebeat_interfaces,
                                                       interface_group_name='interface')

    return parser
