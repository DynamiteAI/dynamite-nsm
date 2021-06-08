# Suricata
Suricata is a leading independent open source threat detection engine that combines intrusion detection and community maintained
rule-sets to quickly identify sophisticated threats.

Within DynamiteNSM, Suricata is used primarily for identifying known suspicious or malicious activity.

By default, Suricata runs the [EmergingThreat Open rule-set](https://rules.emergingthreats.net/open/suricata-4.0/rules/), which is updated daily.


To make sure you are running the latest rules run `sudo dynamite suricata update`.

```bash
sudo dynamite suricata -h
usage: dynamite [-h] {install,uninstall,update,process,config,logs} ...

Suricata @ 192.168.199.1

positional arguments:
  {install,uninstall,update,process,config,logs}
    install             Install Suricata as a standalone component.
    uninstall           Uninstall Suricata this machine.
    update              Install the latest Suricata rule-sets.
    process             Manage local Suricata node processes.
    config              Modify Suricata configurations.
    logs                Attach to various Suricata logs.

optional arguments:
  -h, --help            show this help message and exit

```

## Installation
```bash
sudo dynamite suricata install -h
```

## Configuration
```bash
sudo dynamite suricata config -h
```

### Scripts Configuration
```bash
sudo dynamite suricata config main rules -h
```

## Process Management
```bash
sudo dynamite suricata process -h
```

## View Logs
```bash
sudo dynamite suricata logs -h
```

## Defaults

### Directories

- Installation Directory: `/opt/dynamite/suricata/`
- Configuration Directory: `/etc/dynamite/suricata/`
- Rules Directory: `/etc/dynamite/suricata/rules`
- Logs: `/var/log/dynamite/suricata/`
