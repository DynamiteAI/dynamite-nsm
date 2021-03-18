import types
from typing import Union
import argparse
from dynamite_nsm.cmd import get_dynamite_parser
from dynamite_nsm.cmd import elasticsearch, logstash, kibana, zeek, suricata, filebeat
from dynamite_nsm.service_to_commandline import SingleResponsibilityInterface, MultipleResponsibilityInterface
component_modules = dict(
    elasticsearch=elasticsearch,
    logstash=logstash,
    kibana=kibana,
    zeek=zeek,
    suricata=suricata,
    filebeat=filebeat
)


def invoke_component_interface(args: argparse.Namespace):
    try:
        interface = getattr(component_modules[args.sub_component], args.sub_interface)
    except KeyError:
        raise ModuleNotFoundError(f'{args.sub_component} is not a valid component module.')
    except AttributeError:
        raise ModuleNotFoundError(f'{args.sub_component}.{args.sub_interface} is not a valid interface module.')
    interface.interface.execute(args)


if __name__ == '__main__':
    parser = get_dynamite_parser()
    args = parser.parse_args()
    invoke_component_interface(args)