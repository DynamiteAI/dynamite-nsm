# Monitor

The `monitor` is a convenience `service` that provides a single interface around some of Elasticsearch and Kibana's interfaces. 

```bash
$ sudo dynamite monitor -h

usage: dynamite [-h] {install,uninstall,process} ...

Monitor @ 192.168.194.143

positional arguments:
  {install,uninstall,process}
    install             Install monitor components and configure this system
                        to receive events and alerts from various agents.
    uninstall           Uninstall the monitor components on this machine.
    process             Manage Local Monitor processes.

optional arguments:
  -h, --help            show this help message and exit

```

## Installation
```bash
sudo dynamite monitor install -h
```

## Configuration

The `monitor` service does not present a wrapper interface for underlying configurations.

These configurations must be accessed directly through the [Elasticsearch](/services/04_elasticsearch) or [Kibana](/services/06_kibana) service commands.

```bash
sudo dynamite elasticsearch config -h
sudo dynamite kibana config -h
```


## Process Management
```markdown
sudo dynamite agent process -h
```


## Troubleshooting

| Problem                     | Description                                                                 | Solution                                                                                                                                                                                                                                                                                                                                                                                                        |
|-----------------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Can't Access Web Interfaces | You cannot access `elasticsearch` or `kibana` through their web-interfaces. | Firstly, double check that the services are running: `dynamite monitor process status`. If they are, you may have a host based firewall enabled. By default, CentOS for example, enables `firewalld` service. You may need to modify the ACLs in order allow `9200` and `5601` accessible to outside hosts. Temporarily, you can disable `firewalld` via `systemctl stop firwalld` to verify this is the issue. |