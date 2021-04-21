---
title: __main_select__
---

## Dynamite Commandline Utility

```bash
usage: Dynamite Network Security Monitor [1.0.0] [-h] {elasticsearch,logstash,kibana,zeek,suricata,filebeat,updates} {install,uninstall,config,logs,process}

positional arguments:
  {elasticsearch,logstash,kibana,zeek,suricata,filebeat,updates}
                        A component within the Dynamite stack to manage.
  {install,uninstall,config,logs,process}
                        An action or set of actions that can be performed against a specified component.

optional arguments:
  -h, --help            show this help message and exit

```

## About

DynamiteNSM ships with a powerful commandline utility that wraps the majority of the functionality available within the `services`
modules. 

You can invoke any of the below services and perform a range of operations against that service.