# Filebeat

Filebeat-OSS is a free and open-source log shipper written in GoLang. The utility is capable of forwarding logs to a 
variety of destination types.

DynamiteNSM relies on Filebeat for some initial formatting and normalization of Zeek and Suricata logs and of course
sending the logs on through a supported [connector](/configuration/agent/01_connectors).

```bash
sudo dynamite filebeat -h

usage: dynamite [-h] {install,uninstall,process,config,logs} ...

Filebeat @ 192.168.199.1

positional arguments:
  {install,uninstall,process,config,logs}
    install             Install Filebeat as a standalone component.
    uninstall           Uninstall Filebeat on this machine.
    process             Manage local Filebeat processes.
    config              Modify Filebeat configuration
    logs                Attach to various Filebeat logs.

optional arguments:
  -h, --help            show this help message and exit


```

## Installation
```bash
sudo dynamite filebeat install -h
```

## Configuration
```markdown
sudo dynamite filebeat config -h
```

## Process Management
```markdown
sudo dynamite filebeat process -h
```

## Defaults

### Directories

- Installation Directory: `/opt/dynamite/filebeat/`
- Logs: `/opt/dynamite/filebeat/logs/filebeat`

