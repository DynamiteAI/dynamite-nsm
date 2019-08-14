```
usage: dynamite [-h] [--interface NETWORK_INTERFACE]
                   [--agent-label AGENT_LABEL] [--host HOST] [--port PORT]
                   [--es-host ES_HOST] [--es-port ES_PORT] [--debug]
                   command component

Install/Configure the Dynamite Analysis Framework.

positional arguments:
  command               An action to perform
                        [prepare|install|uninstall|start|stop|status|profile]
  component             The component to perform an action against
                        [agent|logstash|elasticsearch]

optional arguments:
  -h, --help            show this help message and exit
  --interface NETWORK_INTERFACE
                        A network interface to analyze traffic on.
  --agent-label AGENT_LABEL
                        A descriptive label associated with the agent. This
                        could be a location on your network (VLAN01),or the
                        types of servers on a segment (E.G Workstations-US-1).
  --host HOST           A valid Ipv4/Ipv6 address or hostname
  --port PORT           A valid port [1-65535]
  --es-host ES_HOST     Target ES cluster; A valid Ipv4/Ipv6 address or
                        hostname
  --es-port ES_PORT     Target ES cluster; A valid port [1-65535]
  --debug               Include detailed error messages in console.
```