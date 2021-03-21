
import argparse
from typing import Optional
from dynamite_nsm.cmd import elasticsearch, logstash, kibana, zeek, suricata, filebeat


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
