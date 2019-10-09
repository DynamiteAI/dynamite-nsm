## Usage

<p style="color:red" Script MUST be run as root!</p>

```
usage: dynamite.py [-h] [--interface NETWORK_INTERFACE]
                   [--agent-label AGENT_LABEL] [--ls-host LS_HOST]
                   [--ls-port LS_PORT] [--es-host ES_HOST] [--es-port ES_PORT]
                   [--debug]
                   command component

Install/Configure the Dynamite Network Monitor.

positional arguments:
  command               An action to perform [prepare|install|uninstall|start|
                        stop|restart|status|profile|update|point|chpasswd]
  component             The component to perform an action against
                        [agent|monitor|elasticsearch|logstash|kibana|suricata-
                        rules|mirrors|default-configs]

optional arguments:
  -h, --help            show this help message and exit
  --interface NETWORK_INTERFACE
                        A network interface to analyze traffic on.
  --agent-label AGENT_LABEL
                        A descriptive label associated with the agent. This
                        could be a location on your network (VLAN01),or the
                        types of servers on a segment (E.G Workstations-US-1).
  --ls-host LS_HOST     Target Logstash instance; A valid Ipv4/Ipv6 address or
                        hostname
  --ls-port LS_PORT     Target Logstash instance; A valid port [1-65535]
  --es-host ES_HOST     Target ElasticSearch cluster; A valid Ipv4/Ipv6
                        address or hostname
  --es-port ES_PORT     Target ElasticSearch cluster; A valid port [1-65535]
  --debug               Include detailed error messages in console.
```

## Components

### agent 
Zeek + Suricata + FileBeat; responsible for analyzing network traffic on a given interface and forwarding on to LogStash for enrichment.

| Command   | Description                                                                                               | Example                                                                                   |
|-----------|-----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| prepare   | Install required dependencies for agent installation. Requires a`reboot` for changes to go into effect. |`dynamite prepare agent`                                                                  |
| install   | Install agent components (Zeek, Suricata, PF_RING, Oinkmaster).                                          |`dynamite install agent --interface mon0 --agent-label honeypot1 --ls-host 160.1.134.145` |
| uninstall | Uninstall agent components (Zeek, Suricata, PF_RING, Oinkmaster).                                         |`dynamite uninstall agent`                                                                |
| start     | Start the agent processes.                                                                                |`dynamite start agent`                                                                    |
| stop      | Stop the agent processes.                                                                                 |`dynamite stop agent`                                                                     |
| restart   | Restart the agent processes.                                                                              |`dynamite restart agent`                                                                  |
| status    | Return the status of agent running processes.                                                             |`dynamite status agent`                                                                   |
| profile   | Run a series of checks to determine if agent is installed properly.                                       |`dynamite profile agent`                                                                  |
| point     | Point the agent to a new LogStash host.                                                                   |`dynamite point agent --ls-host 160.1.134.130 --ls-port 5044`                             |

### monitor
ElasticSearch + Logstash + Kibana; combines ElastiFlow and Synesis for normalization and enrichment of NetFlows/Zeek and Suricata logs.

| Command   | Description                                                                                          | Example                      |
|-----------|------------------------------------------------------------------------------------------------------|------------------------------|
| install   | Install monitor components (ElasticSearch, Kibana (And dashboards), LogStash (And configurations)). |`dynamite install monitor`   |
| uninstall | Uninstall monitor components ElasticSearch, Kibana (And dashboards), LogStash (And configurations).  |`dynamite uninstall monitor` |
| start     | Start the monitor processes.                                                                         |`dynamite start monitor`    |
| stop      | Stop the monitor processes.                                                                          |`dynamite stop monitor`     |
| restart   | Restart the monitor processes.                                                                       |`dynamite restart monitor`  |
| status    | Return the status of monitor running processes.                                                      |`dynamite status monitor`   |
| profile   | Run a series of checks to determine if monitor is installed properly.                                |`dynamite profile monitor`  |


### elasticsearch
A standalone ElasticSearch instance; for large-scale deployments where a single monitor instance isn't feasible.

| Command   | Description                                                                 | Example                             |
|-----------|-----------------------------------------------------------------------------|-------------------------------------|
| install   | Install ElasticSearch.                                                     |`dynamite install elasticsearch`    |
| uninstall | Uninstall ElasticSearch.                                                    |`dynamite uninstall elasticsearch` |
| start     | Start ElasticSearch process.                                                |`dynamite start elasticsearch`     |
| stop      | Stop ElasticSearch process.                                                 |`dynamite stop elasticsearch`      |
| restart   | Restart ElasticSearch process.                                              |`dynamite restart elasticsearch`   |
| status    | Return the status of the ElasticSearch process.                             |`dynamite status elasticsearch`    |
| profile   | Run a series of checks to determine if ElasticSearch is installed properly. |`dynamite profile elasticsearch`   |

### logstash
A standalone Logstash instance; for large-scale deployments where single monitor instance isn't feasible.

| Command   | Description                                                            | Example                                                           |
|-----------|------------------------------------------------------------------------|-------------------------------------------------------------------|
| install   | Installs LogStash.                                                     |`dynamite install logstash --es-host 143.129.22.6 --es-port 9200` |
| uninstall | Uninstall LogStash.                                                    |`dynamite uninstall logstash`                                    |
| start     | Start LogStash process.                                                |`dynamite start logstash`                                        |
| stop      | Stop LogStash process.                                                 |`dynamite stop logstash`                                         |
| restart   | Restart LogStash process.                                              |`dynamite restart logstash`                                      |
| status    | Return the status of the LogStash process.                             |`dynamite status logstash`                                       |
| profile   | Run a series of checks to determine if LogStash is installed properly. |`dynamite profile logstash`                                      |

### kibana
A standalone Kibana instance.

| Command   | Description                                                          | Example                                                         |
|-----------|----------------------------------------------------------------------|-----------------------------------------------------------------|
| install   | Installs Kibana.                                                     |`dynamite install kibana --es-host 143.129.22.6 --es-port 9200` |
| uninstall | Uninstall Kibana.                                                    |`dynamite uninstall kibana`                                    |
| start     | Start Kibana process.                                                |`dynamite start kibana`                                        |
| stop      | Stop Kibana process.                                                 |`dynamite stop kibana`                                         |
| restart   | Restart Kibana process.                                              |`dynamite restart kibana`                                      |
| status    | Return the status of the Kibana process.                             |`dynamite status kibana`                                       |
| profile   | Run a series of checks to determine if Kibana is installed properly. |`dynamite profile kibana`                                      |

### suricata-rules

| Command | Description                                                    | Example                           |
|---------|----------------------------------------------------------------|-----------------------------------|
| update  | Update Suricata rule sets (If Suricata is currently installed) |`dynamite update suricata-rules` |


### mirrors

| Command | Description                                                    | Example                   |
|---------|----------------------------------------------------------------|---------------------------|
| update  | Update mirrors used for retrieving various software components |`dynamite update mirrors` |

### default-configs

```bash
WARNING OVERWRITES ANY CUSTOM CONFIGURATIONS!
```

| Command | Description                                                                    | Example                           |
|---------|--------------------------------------------------------------------------------|-----------------------------------|
| update  | Update default configurations for various installed components (monitor/agent) | `dynamite update default-configs` |


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
| Suricata Log | `/var/dynamite/suricata/log/suricata/suricata.log` |
| Event JSON   | `/var/dynamite/suricata/log/suricata/eve.json`     |

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