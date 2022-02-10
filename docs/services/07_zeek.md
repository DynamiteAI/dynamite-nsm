# Zeek
Zeek (formerly Bro) is a free and open-source software network analysis framework. It provides an extremely powerful scripting
language that can be used for everything from protocol parsing to file carving.

Within DynamiteNSM, Zeek serves as the primary mechanism for harvesting metadata around network conversations.

Through its scripting framework, Zeek is capable of generating [many logs](https://docs.zeek.org/en/master/script-reference/log-files.html) that provide rich context
around and alerts.

```bash
$ dynamite zeek -h 

usage: dynamite [-h] {install,uninstall,process,config,logs} ...

Zeek @ 192.168.199.1

positional arguments:
  {install,uninstall,process,config,logs}
    install             Install Zeek as a standalone component.
    uninstall           Uninstall Zeek on this machine.
    process             Manage local Zeek node processes.
    config              Modify Zeek configurations.
    logs                Attach to various Zeek logs.

optional arguments:
  -h, --help            show this help message and exit



```

## Installation
```bash
sudo dynamite zeek install -h
```

## Configuration
```bash
dynamite zeek config -h
```

### Scripts Configuration
```bash
dynamite zeek config site scripts -h
```

## Process Management
```bash
sudo dynamite zeek process -h
```

## View Logs
```bash
dynamite zeek logs -h
```

## Defaults

### Directories

- Installation Directory: `/opt/dynamite/zeek/`
- Configuration Directory: `/etc/dynamite/zeek`
- Logs: `/opt/dynamite/zeek/logs/current/`
