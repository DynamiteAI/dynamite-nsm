# Commandline Overview

## Navigating the Commandline

Since DynamiteNSM `0.7.0` the commandline tool has aligned itself to components. There are currently 8 components in the DynamiteNSM platform, each component has its own set of actions.

To get a list of component actions simply run:

```
dynamite <component> -h
```

To get a list of options for a given component action run:

```
dynamite <component> <action> -h
```



## Usage


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


### Components


#### agent 

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

##### Examples

| Command                                                                                                                                         | Description                                                                                |
|-------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `dynamite agent install --capture-interfaces eth0 --analyzers zeek suricata --targets remote-host.me:5044`                                      | Install an agent with Zeek and Suricata enabled and point it to a remote monitor instance. |
| `dynamite agent install --capture-interfaces eth0 --analyzers suricata --targets remote-host.me:9092 192.168.4.30:9092 --kafka-topic raw-logs`  | Install an agent with Suricata only and point it to, two remote two Kafka brokers.         |
| `dynamite agent config`                                                                                                                         | Access agent config TUIs.


#### monitor

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

##### Examples

| Command                                                       | Description                                                                        |
|---------------------------------------------------------------|------------------------------------------------------------------------------------|
| `dynamite monitor install --ls-heap-size=6 --es-heap-size=12` | Install monitor with LogStash heap-size of 6GB and ElasticSearch heap-size of 12GB |
| `dynamite monitor install --kb-listen-port 9001`              | Install monitor with Kibana on an alternative port.                                |

#### lab <sub>`experimental`</sub>

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


#### elasticsearch

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

#### logstash
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

#### kibana
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

#### updates

Download the latest default configurations and mirrors used when installing the above components.

```
usage: dynamite updates [-h] {install} ...

positional arguments:
  {install}
    install   Install the latest default configurations and mirrors.

optional arguments:
  -h, --help  show this help message and exit
```

