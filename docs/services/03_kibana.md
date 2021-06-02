# Kibana
Kibana is a free and open-source frontend application that sits on top of Elasticsearch, and provides search and data visualization capabilities.

DynamiteNSM automatically sets up Kibana with a rich collection of [data visualizations and views](/guides/for_security_analysts/kibana/packages/dynamite_investigator/)
useful for exploring your network from a variety of different perspectives.

Additional packages can be installed via the `kibana package` utility.

```bash
dynamite kibana -h
usage: dynamite [-h] {install,uninstall,process,config,package} ...

Kibana @ 192.168.194.143

positional arguments:
  {install,uninstall,process,config,package}
    install             Install Kibana as a standalone component.
    uninstall           Uninstall Kibana on this machine.
    process             Manage local Kibana node processes.
    config              Modify Kibana configurations.
    package             Add, remove, and manage packages created for Dynamite Kibana.

optional arguments:
  -h, --help            show this help message and exit

```

## Installation
```bash
sudo dynamite kibana install -h
```

## Configuration
```markdown
sudo dynamite kibana config -h
```

## Process Management
```markdown
sudo dynamite kibana process -h
```

## Defaults

### Directories

- Configuration Directory: `/etc/dynamite/kibana/`
- Installation Directory:  `/opt/dynamite/kibana/`
- Logs: `/var/log/dynamite/kibana/`

### Access


- API URL: `http://<management-ip>:5601`
- Default User: `admin`
- Default Password: `admin`
