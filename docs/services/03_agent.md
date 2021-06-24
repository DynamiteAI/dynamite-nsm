# Agent

The `agent` is a convenience `service` that provides a single interface around some of Elasticsearch and Kibana's interfaces. 

```bash
$ sudo dynamite agent -h

usage: dynamite [-h] {install,uninstall,process,optimize} ...

Agent @ 192.168.199.1

positional arguments:
  {install,uninstall,process,optimize}
    install             Install agent components and configure this system as
                        a sensor.
    uninstall           Uninstall all the agent components on this machine.
    process             Manage local Agent processes.
    optimize            Automatically adjust how resources are allocated
                        between Zeek and Suricata.

optional arguments:
  -h, --help            show this help message and exit
```

## Installation
```bash
sudo dynamite agent install -h
```

## Configuration

The `agent` service does not present a wrapper interface for underlying configurations.

These configurations must be accessed directly through the [Zeek](/services/07_zeek), [Suricata](/services/08_suricata), 
or [Filebeat](/services/09_filebeat) service commands.

```bash
sudo dynamite elasticsearch config -h
sudo dynamite kibana config -h
```


## Process Management
```markdown
sudo dynamite agent process -h
```