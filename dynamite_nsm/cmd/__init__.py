import argparse

from dynamite_nsm import service_to_commandline
from dynamite_nsm.cmd import elasticsearch, logstash, kibana, zeek, suricata, filebeat
from dynamite_nsm.utilities import get_primary_ip_address


def get_dynamite_parser():
    parser = argparse.ArgumentParser(description=f'Dynamite @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()

    elasticsearch_interfaces = elasticsearch.get_interfaces()
    elasticsearch_parser = subparsers.add_parser(name='elasticsearch')
    elasticsearch_parser.set_defaults(sub_component='elasticsearch')
    elasticsearch_subparsers = elasticsearch_parser.add_subparsers()

    logstash_interfaces = logstash.get_interfaces()
    logstash_parser = subparsers.add_parser(name='logstash')
    logstash_parser.set_defaults(sub_component='logstash')
    logstash_subparsers = logstash_parser.add_subparsers()

    kibana_interfaces = kibana.get_interfaces()
    kibana_parser = subparsers.add_parser(name='kibana')
    kibana_parser.set_defaults(sub_component='logstash')
    kibana_subparsers = kibana_parser.add_subparsers()

    zeek_interfaces = zeek.get_interfaces()
    zeek_parser = subparsers.add_parser(name='zeek')
    zeek_parser.set_defaults(sub_component='zeek')
    zeek_subparsers = zeek_parser.add_subparsers()

    suricata_interfaces = suricata.get_interfaces()
    suricata_parser = subparsers.add_parser(name='suricata')
    suricata_parser.set_defaults(sub_component='suricata')
    suricata_subparsers = suricata_parser.add_subparsers()

    filebeat_interfaces = filebeat.get_interfaces()
    filebeat_parser = subparsers.add_parser(name='filebeat')
    filebeat_parser.set_defaults(sub_component='filebeat')
    filebeat_subparsers = filebeat_parser.add_subparsers()

    service_to_commandline.append_interfaces_to_parser(elasticsearch_subparsers, interfaces=elasticsearch_interfaces)
    service_to_commandline.append_interfaces_to_parser(logstash_subparsers, interfaces=logstash_interfaces)
    service_to_commandline.append_interfaces_to_parser(kibana_subparsers, interfaces=kibana_interfaces)
    service_to_commandline.append_interfaces_to_parser(zeek_subparsers, interfaces=zeek_interfaces)
    service_to_commandline.append_interfaces_to_parser(suricata_subparsers, interfaces=suricata_interfaces)
    service_to_commandline.append_interfaces_to_parser(filebeat_subparsers, interfaces=filebeat_interfaces)

    return parser
