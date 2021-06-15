# Logstash
Logstash is an open-source server-side data processing pipeline that allows you to collect data from a variety of sources, 
transform it on the fly, and send it to your desired destination.

> ⓘ Logstash is an optional component within the Dynamite stack and is not installed as part of the `monitor`.
> DynamiteNSM does not currently provide an automated integration strategy with Logstash. 
> 
> Once installed, Logstash must be manually configured to listen for events from the `agent`, forwarding them downstream
> to a collector of your choice.



DynamiteNSM pre-configures Logstash with several useful defaults, and automatically optimizes its use of the JVM heap.

```bash
$ sudo dynamite logstash -h

usage: dynamite [-h] {install,uninstall,process,config} ...

Logstash @ 192.168.194.143

positional arguments:
  {install,uninstall,process,config}
    install             Install Logstash as a standalone component.
    uninstall           Uninstall Logstash on this machine.
    process             Manage local Logstash instance.
    config              Modify Logstash configurations.

optional arguments:
  -h, --help            show this help message and exit

```

## Installation
```bash
sudo dynamite logstash install -h
```

## Configuration
```markdown
sudo dynamite logstash config -h
```

## Process Management
```markdown
sudo dynamite logstash process -h
```

## Defaults

### Directories

- Configuration Directory: `/etc/dynamite/logstash/`
- Installation Directory:  `/opt/dynamite/logstash/`
- Logs: `/var/log/dynamite/logstash/`
- JAVA_HOME: `/usr/lib/jvm//jdk-13.0.1`
