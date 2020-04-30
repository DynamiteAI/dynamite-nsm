# Usage

<p style="color:red" Script MUST be run as root!</p>

```
usage: dynamite [-h]
                {agent-dependencies,agent,monitor,elasticsearch,logstash,kibana,lab,updates}
                ...

Discover your network.

positional arguments:
  {agent-dependencies,agent,monitor,elasticsearch,logstash,kibana,lab,updates}
    agent-dependencies  Install Linux kernel development headers required for
                        agent installation.
    agent               Install, configure, manage the Dynamite Agent.
    monitor             Install, configure, manage standalone ELK
                        [ElasticSearch + Logstash + Kibana] instance.
    elasticsearch       Install, configure, manage ElasticSearch.
    logstash            Install, configure, manage LogStash.
    kibana              Install, configure, manage Kibana with pre-built
                        Dynamite Analytic Views.
    lab                 Install, configure, manage the Dynamite Lab.
    updates             Update to the latest default configurations and
                        mirrors.

optional arguments:
  -h, --help            show this help message and exit
```

## Components

### agent 
Responsible for analyzing network traffic on a given interface and forwarding on to LogStash (or Kafka) for enrichment.

```
usage: dynamite agent [-h]
                      {config,install,uninstall,start,stop,restart,status,update}
                      ...

positional arguments:
  {config,install,uninstall,start,stop,restart,status,update}
    config              Configure Agent.
    install             Install Agent.
    uninstall           Uninstall Agent.
    start               Start Agent.
    stop                Stop Agent.
    restart             Restart Agent.
    status              Status Agent.
    update              Update Agent's EmergingThreat Signatures (If Suricata analyzer is installed).

optional arguments:
  -h, --help            show this help message and exit
```

#### Examples

| Command                                                                                                                                         | Description                                                                                |
|-------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `dynamite agent install --capture-interfaces eth0 --analyzers zeek suricata --targets remote-host.me:5044`                                      | Install an agent with Zeek and Suricata enabled and point it to a remote monitor instance. |
| `dynamite agent install --capture-interfaces eth0 --analyzers suricata --targets remote-host.me:9092 192.168.4.30:9092 --kafka-topic raw-logs`  | Install an agent with Suricata only and point it to, two remote two Kafka brokers.         |
| `dynamite agent config`                                                                                                                         | Access agent config TUIs.


### monitor
All the monitoring components (ElasticStack & Dynamite Normalization Templates and Visualisations) on a single instance!

```
usage: dynamite monitor [-h]
                        {chpasswd,install,uninstall,start,stop,restart,status}
                        ...

positional arguments:
  {chpasswd,install,uninstall,start,stop,restart,status}
    chpasswd            Change Monitor Passwords.
    install             Install Monitor.
    uninstall           Uninstall Monitor.
    start               Start Monitor.
    stop                Stop Monitor.
    restart             Restart Monitor.
    status              Status Monitor.

optional arguments:
  -h, --help            show this help message and exit
```

#### Examples
| Command                                                       | Description                                                                        |
|---------------------------------------------------------------|------------------------------------------------------------------------------------|
| `dynamite monitor install --ls-heap-size=6 --es-heap-size=12` | Install monitor with LogStash heap-size of 6GB and ElasticSearch heap-size of 12GB |
| `dynamite monitor install --kb-listen-port 9001`              | Install monitor with Kibana on an alternative port.                                |

### lab <sub>`experimental`</sub>

Interact with your network data inside JupyterHub. 

Powered by [DynamiteSDK](https://github.com/DynamiteAI/dynamite-sdk-lite).

```
usage: dynamite lab [-h] {install,uninstall,start,stop,restart,status} ...

positional arguments:
  {install,uninstall,start,stop,restart,status}
    install             Install Dynamite Lab.
    uninstall           Uninstall Lab.
    start               Start Lab.
    stop                Stop Lab.
    restart             Restart Lab.
    status              Status Lab.

optional arguments:
  -h, --help            show this help message and exit
```


### elasticsearch

A standalone ElasticSearch instance; for large-scale deployments where a single monitor instance isn't feasible.

```
usage: dynamite elasticsearch [-h]
                              {chpasswd,install,uninstall,start,stop,restart,status}
                              ...

positional arguments:
  {chpasswd,install,uninstall,start,stop,restart,status}
    chpasswd            Change ElasticSearch Password.
    install             Install ElasticSearch.
    uninstall           Uninstall ElasticSearch.
    start               Start ElasticSearch.
    stop                Stop ElasticSearch.
    restart             Restart ElasticSearch.
    status              Status ElasticSearch.

optional arguments:
  -h, --help            show this help message and exit
```

### logstash
A standalone LogStash instance; for large-scale deployments where single monitor instance isn't feasible.

```
usage: dynamite logstash [-h]
                         {chpasswd,install,uninstall,start,stop,restart,status}
                         ...

positional arguments:
  {chpasswd,install,uninstall,start,stop,restart,status}
    chpasswd            Change password LogStash uses for connecting to
                        ElasticSearch.
    install             Install LogStash.
    uninstall           Uninstall LogStash.
    start               Start LogStash.
    stop                Stop LogStash.
    restart             Restart LogStash.
    status              Status LogStash.

optional arguments:
  -h, --help            show this help message and exit
```

### kibana
A standalone Kibana instance.

```
usage: dynamite kibana [-h]
                       {chpasswd,install,uninstall,start,stop,restart,status}
                       ...

positional arguments:
  {chpasswd,install,uninstall,start,stop,restart,status}
    chpasswd            Change password Kibana uses for connecting to
                        ElasticSearch.
    install             Install Kibana.
    uninstall           Uninstall Kibana.
    start               Start Kibana.
    stop                Stop Kibana.
    restart             Restart Kibana.
    status              Status Kibana.

optional arguments:
  -h, --help            show this help message and exit
```

### updates

Download the latest default configurations and mirrors used when installing the above components.

```
usage: dynamite updates [-h] {install} ...

positional arguments:
  {install}
    install   Install the latest default configurations and mirrors.

optional arguments:
  -h, --help  show this help message and exit
```

## Advanced Configuration Options

### Agent Files

#### Filebeat
Filebeat functions as a  log forwarder, and is the agent component responsible for forwarding Zeek/Suricata logs to LogStash.

| Config                 | Location                              |
|------------------------|---------------------------------------|
| Filebeat Configuration | `/opt/dynamite/filebeat/filebeat.yml` |

| Log | Location                               |
|-----------------|----------------------------------------|
| Filebeat Log    | `/opt/dynamite/filebeat/logs/filebeat` |

#### Zeek

Zeek is responsible for generating a variety of logs that representative of network conversations and application protocols. 


| Config               | Location                            |
|----------------------|-------------------------------------|
| Enabled Zeek Scripts | `/etc/dynamite/zeek/site/local.bro` |
| Node Configuration   | `/opt/dynamite/zeek/etc/node.cfg`   |
| Script Directory     | `/etc/dynamite/zeek/policy/`        |

| Log                | Location                   |
|--------------------|----------------------------|
| Zeek Log Directory | `/opt/dynamite/zeek/logs/` |

#### Suricata

Suricata is responsible for generating alert based detections, and relies on open-source EmergingThreat rulesets to accomplish this.

| Config                 | Location                               |
|------------------------|----------------------------------------|
| Suricata Configuration | `/etc/dynamite/suricata/suricata.yaml` |
| Rules Directory        | `/etc/dynamite/suricata/rules/`        |

| Log          | Location                                           |
|--------------|----------------------------------------------------|
| Suricata Log | `/var/dynamite/suricata/suricata.log`              |
| Event JSON   | `/var/dynamite/suricata/eve.json`                  |

### Monitor Configuration Files

#### ElasticSearch

ElasticSearch functions as the main location for indexing normalized log files.

| Config                               | Location                                        |
|--------------------------------------|-------------------------------------------------|
| ElasticSearch Configuration          | `/etc/dynamite/elasticsearch/elasticsearch.yml` |
| Java memory provisioning (heap-size) | `/etc/dynamite/elasticsearch/jvm.options`       |


| Log         | Location                                             |
|-------------|------------------------------------------------------|
| Cluster Log | /var/log/dynamite/elasticsearch/dynamite-cluster.log |

#### LogStash

LogStash is responsible for raw log normalization and enrichment.

| Config                               | Location                                   |
|--------------------------------------|--------------------------------------------|
| Logstash Configuration               | `/etc/dynamite/logstash/logstash.yml`      |
| Java memory provisioning (heap-size) | `/etc/dynamite/logstash/jvm.options`       |
| Pipelines                            | `/etc/dynamite/logstash/pipelines.yml`     |
| ElastiFlow Config Directory          | `/etc/dynamite/logstash/elastiflow/conf.d` |
| Synesis Config Directory             | `/etc/dynamite/logstash/synesis/conf.d`    |


| Log         | Location                                             |
|-------------|------------------------------------------------------|
| LogStash Log | /var/log/dynamite/logstash/logstash-plain.log       |


#### Kibana

Kibana is responsible for the visualization of Zeek/Suricata logs, and to provide a simple interface for searching these logs.

| Config               | Location                          |
|----------------------|-----------------------------------|
| Kibana Configuration | `/etc/dynamite/kibana/kibana.yml` |

| Log         | Location                                 |
|-------------|------------------------------------------|
| Kibana Log | /var/log/dynamite/kibana/kibana.log       |
