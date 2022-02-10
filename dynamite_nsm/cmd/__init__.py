import argparse
from typing import Optional

from dynamite_nsm.cmd import setup, agent, monitor, elasticsearch, logstash, kibana, suricata, zeek, filebeat, \
    updates, auth

component_modules = dict(
        setup=setup,
        agent=agent,
        monitor=monitor,
        elasticsearch=elasticsearch,
        logstash=logstash,
        kibana=kibana,
        package=kibana.package,
        zeek=zeek,
        suricata=suricata,
        filebeat=filebeat,
        updates=updates,
        auth=auth
    )


def process_arguments(args: argparse.Namespace, component: Optional[str], interface: Optional[str] = None,
                      sub_interface: Optional[str] = None, print_help_on_error: Optional[bool] = False):
    """
    Selects the proper execution context given an argparse.Namespace, executes the namespace against that context
    :param args: The argparse.Namespace object containing all the user selected commandline arguments
    :param component: A string representing the name of the component (elasticsearch, logstash, kibana, zeek, suricata,
                      or filebeat)
    :param interface: A string representing the name of the interface (E.G config, install, process, logs, uninstall)
    :param sub_interface: A string representing a sub-interface (for example a config or log name)
    :return: The results of the executed context.
    """
    component_interface = None
    try:
        component_interface = getattr(component_modules[component], interface)
        if sub_interface:
            component_interface = getattr(component_interface, sub_interface)
    except KeyError:
        raise ModuleNotFoundError(f'{component} is not a valid component module.')
    except AttributeError:
        if not print_help_on_error:
            raise ModuleNotFoundError(f'{component}.{interface} is not a valid interface module.')
        component_modules[component].get_action_parser().print_help()

    try:
        return component_interface.interface.execute(args)
    except AttributeError as e:
        component_modules[component].get_action_parser().print_help()
