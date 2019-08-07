## Dynamite Network Security Monitor

[dynamite-logo]: raw/master/img/dynamite_182x44.png

##### Dynamite-NSM is an network security monitor and log-management solution with an emphasis on *very* fast deployment, minimal configuration, and intuitive management.

Unlike other NSMs Dynamite can be installed without the need of downloading an ISO image. It is offered as standalone commandline utility implemented in pure Python 2/3.

### What's in the Box?

#### Agent
| Component   | Description                                                                                                                                                                                                           |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Zeek        | Previously Bro, Zeek is a powerful network analysis framework that is much different from your typical IDS, capable of enumerating detailed information surrounding network connections and their underlying protocols.                                      |
| PF_RING     | A new type of network socket that dramatically improves the packet capture speed. It is used in conjunction with the above components.                                                                                |
| Filebeat    | A powerful log forwarder, with a built in queue mechanisms, and a pressure sensitive protocol that works in conjunction with Logstash.                                                                                |


#### Monitor

| Component                                              | Description                                                                                                         |
|--------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| Logstash [7.2.0]                                       | A server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it. |
| Elasticsearch [7.2.0]                                  | A distributed, RESTful search and analytics engine.                                                            |
| Kibana [7.2.0]                                         | A web-app that allows you to visualize your Elasticsearch data                                                      |
| [ElastiFlow™](https://github.com/robcowart/elastiflow) | Provides network flow data collection and visualization using the Elastic Stack.                                    |


### Getting Started

While there are quite a few components that are a part of Dynamite-NSM. Standing up a standalone agent/monitor deployment is very simple.

#### Monitor (Standalone all components installed)

##### Specs
```
Linux Kernel: 2.6.32+
16 GB of RAM at least 4 CPU
```
##### Setup

Install the monitoring components all on the same machine.
```bash
dynamite install monitor
```

Start the monitor. The Kibana UI can be found at: http://localhost:5601
```bash
dynamite start monitor
```

#### Agent

##### Specs
```
Linux Kernel: 2.6.32+
4+ GB of RAM at least 2 CPU
```

##### Setup
Prepare the agent, this installs any required kernel-headers needed to install the PF_RING kernel module. 

```bash
dynamite prepare agent
```

Reboot, and install the agent. This process can take between 10 and 40 minutes depending on your specs.

```bash
dynamite install agent --interface en01 --agent-label VLAN-001 --host my-monitor-host-or-ip.local --port 5044
```

Start the agent
```bash
dynamite start agent
```
