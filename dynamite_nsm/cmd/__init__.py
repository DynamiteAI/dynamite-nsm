import argparse

from dynamite_nsm import service_to_commandline
from dynamite_nsm.cmd import elasticsearch, logstash, kibana, zeek, suricata, filebeat
from dynamite_nsm.utilities import get_primary_ip_address

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f'Dynamite @ {get_primary_ip_address()}')
    subparsers = parser.add_subparsers()

    elasticsearch_interfaces = elasticsearch.get_interfaces()
    elasticsearch_parser = subparsers.add_parser(name='elasticsearch')
    elasticsearch_subparsers = elasticsearch_parser.add_subparsers()

    logstash_interfaces = logstash.get_interfaces()
    logstash_parser = subparsers.add_parser(name='logstash')
    logstash_subparsers = logstash_parser.add_subparsers()


    service_to_commandline.append_interfaces_to_parser(elasticsearch_subparsers, interfaces=elasticsearch_interfaces)
    service_to_commandline.append_interfaces_to_parser(logstash_subparsers, interfaces=logstash_interfaces)

    parser.parse_args()
