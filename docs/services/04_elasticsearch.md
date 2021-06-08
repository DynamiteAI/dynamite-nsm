# Elasticsearch

Elasticsearch is a distributed, open-source search and analytics engine built on Apache Lucene and developed in Java.
Within DynamiteNSM it is used to store all network events and alerts that have been acquired and normalized by the agent.

DynamiteNSM pre-configures Elasticsearch with several useful defaults, and automatically optimizes its use of the JVM heap.

```bash
sudo dynamite elasticsearch -h
usage: dynamite [-h] {install,uninstall,process,config} ...

Elasticsearch @ 192.168.194.143

positional arguments:
  {install,uninstall,process,config}
    install             Install Elasticsearch as a standalone component.
    uninstall           Uninstall Elasticsearch on this machine.
    process             Manage local Elasticsearch node processes.
    config              Modify Elasticsearch configurations.

optional arguments:
  -h, --help            show this help message and exit
```

## Installation
```bash
sudo dynamite elasticsearch install -h
```

## Configuration
```markdown
sudo dynamite elasticsearch config -h
```

## Process Management
```markdown
sudo dynamite elasticsearch process -h
```

## Defaults

### Directories

- Configuration Directory: `/etc/dynamite/elasticsearch/`
- Installation Directory:  `/opt/dynamite/elasticsearch/`
- Logs: `/var/log/dynamite/elasticsearch/`
- JAVA_HOME: `/usr/lib/jvm//jdk-13.0.1`

### Access

- API URL: `https://<management-ip>:9200`
- Default User: `admin`
- Default Password: `admin`

### Troubleshooting

#### Elasticsearch won't start

**Symptoms**: You have started `elasticsearch` via the commandline utility or `systemctl` you wait 30 seconds and run the 
`sudo dynamite elasticsearch process status` command, and receive the following.

```markdown
╒════════════════════╤═════════════════════════════════════════════╕
│ Service            │ elasticsearch.process                       │
├────────────────────┼─────────────────────────────────────────────┤
│ Running            │ no                                          │
├────────────────────┼─────────────────────────────────────────────┤
│ Enabled on Startup │ yes                                         │
├────────────────────┼─────────────────────────────────────────────┤
│ Logs               │ /var/log/dynamite/elasticsearch/            │
├────────────────────┼─────────────────────────────────────────────┤
│ Command            │ sudo systemctl status elasticsearch.service │
├────────────────────┼─────────────────────────────────────────────┤
│ Exit Code          │ 3                                           │
╘════════════════════╧═════════════════════════════════════════════╛
```

| Problem          | Description                                                                                                                                                                                                                           | Solution                                                                                                                                                                                                                                                                                                                                                                                               |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Out of Memory    | `elasticsearch` needs to be able to provision a certain amount of heap space (memory) at runtime.  As the document store grows, various operations become more memory intensive and can prevent `elasticsearch` from starting         | Check the `/var/log/dynamite/elasticsearch/dynamite-cluster.log` for a message resembling the following: `There is insufficient memory for the Java Runtime Environment to continue.` If an entry like this is found you must increase the amount of memory on the machine. `sudo systemctl status elasticsearch` or `sudo dynamite elasticsearch process status --verbose` may also provide insights. |
| Misconfiguration | The `elasticsearch.yaml` controls the behavior of `elasticsearch` at runtime. It conforms to `yaml` format. If an invalid value is given or the `yaml` specification violated an error will be logged and `elasticsearch` will crash. | Use a tool like [yamlint](https://github.com/adrienverge/yamllint#installation) to identify obvious issues. Check the Check the  `/var/log/dynamite/elasticsearch/dynamite-cluster.log` for misconfiguration hints.                                                                                                                                                                                    |

