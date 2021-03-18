import argparse

from dynamite_nsm.cmd import elasticsearch, logstash, kibana, zeek, suricata, filebeat
from dynamite_nsm.cmd import get_dynamite_parser







if __name__ == '__main__':
    parser = get_dynamite_parser()
    args = parser.parse_args()
    print(args)
    exit(0)
