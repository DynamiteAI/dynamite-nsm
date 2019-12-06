<a href="http://dynamite.ai"><img src="https://github.com/vlabsio/dynamite-nsm/raw/master/img/dynamite-analytics.png" width="350" height="auto"></a>


## Dynamite Network Security Monitor

#### [Dynamite-NSM](http://dynamite.ai) is a free Network Security Monitor (NSM), built on top of several leading, enterprise-grade technologies. The tool provides network and cybersecurity operators with holistic insights into their networks while giving them the ability to deep-dive into lower-level activities.

The solution presents powerful dashboards, giving comprehensive view into performance and threat-based metrics. Dynamite-NSM can be easily deployed in different environments including high-speed data centers, small-to-large enterprises, IoT & industrial networks, and even at home.

Dynamite-NSM handles massive volumes of network traffic through scalable ingestion and optimized network sensors. The solution includes two key components: the agent and the monitor. The agent analyzes and forwards network events, while the monitor processes incoming events and displays analytic information.

The monitor component builds upon the ELK stack (ElasticSearch, LogStash, Kibana) and is coupled with the fine-tuned Zeek sensor (aka Bro), flow data inputs (NetFlow, sFlow, IPFIX), and Suricata IDS security alerts. Dynamite-NSM now includes the DynamiteLab component made of the python API for easy data access and integrated JupyterHub hosted notebooks as the data science environment. 

Dynamite-NSM is designed to be deployed very quickly with minimal configuration. Unlike many other tools, it can be installed and managed with a standalone command-line utility. The system is inherently passive without disruption to the network. There is no need to install agents on every computer, perform network scans, or directly interact with network assets. To start receiving analytics, we just connect agents and optional flow sources to the monitor.


Dynamite NSM can be installed and managed through a commandline utility implemented in pure Python.

No need to download a huge ISO image or install a dedicated operating system! 

**It is compatible with both Python2 and 3, across these [Linux distributions](SUPPORTED_OSs.md).**

#### Install With...

```bash
python setup.py install
```

**...And checkout the** [Wiki](https://github.com/DynamiteAI/dynamite-nsm/wiki).
<p float="center">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/Dynamite%20Components.jpeg"  width="70%" height="auto">
</p>

### The Agent

**Agents are scattered throughout your environment, and bind to a network interface (typically a mirrored port), after which traffic is forwarded to the monitor for enrichment and indexing.**

| Component   | Description                                                                                                                                                                                                                                                      |
|-------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Zeek [2.6.1]](https://github.com/zeek/zeek)           | Previously Bro, Zeek is a powerful network analysis framework that is differs from your typical IDS. It is capable of enumerating detailed information surrounding network connections and their underlying protocols.|
| [Suricata [4.1.4]](https://github.com/OISF/suricata)   | Suricata is an Intrusion Detection System (IDS), powered by the latest open [EmergingThreat](https://doc.emergingthreats.net/) rule-sets.
| [Oinkmaster [2.0]](http://oinkmaster.sourceforge.net/download.shtml)| A script to automate management of Suricata rule-sets, and keep rules up-to-date.
| [PF_RING [7.4.0]](https://github.com/ntop/PF_RING)     | A new type of network socket that dramatically improves the packet capture speed. It is used in conjunction with the Zeek to improve packet analysis.                                                                 |
| [Filebeat [7.2.0]](https://github.com/elastic/beats)   | A powerful log forwarder, with a built in queue mechanisms, and a pressure sensitive protocol that works in conjunction with Logstash.                                                                                |

### The Monitor

**Your monitor is responsible for parsing, enriching, indexing, and visualizing analyzed traffic sent from multiple agents or NetFlow exporters.**

| Component                                              | Description                                                                                                                     |
|--------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| [Logstash [7.2.0]](https://github.com/elastic/logstash)            | A server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it. |
| [Elasticsearch [7.2.0]](https://github.com/elastic/elasticsearch)  | A distributed, RESTful search and analytics engine.                                                                 |
| [Kibana [7.2.0]](https://github.com/elastic/kibana)                | A web-app that allows you to visualize your Elasticsearch data                                                      |
| [ElastiFlow™ [3.5.0]](https://github.com/robcowart/elastiflow) | Provides network flow (**and now Zeek!**) data collection and visualization.                                                                |
| [Synesis [1.1.0]](https://github.com/robcowart/synesis_lite_suricata)| Provides Suricata data normalization and visualization.|

### Dynamite Dashboards
Dynamite monitor is built on top of the ElasticStack, and makes full use of Kibana for visualizing a variety of network metrics.

#### Event View
Get direct insight into your network traffic with the powerful events view, compatible with both the provided agent or NetFlow exporters!
<p float="left">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-flows.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-geo.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-top-services.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-top-talkers.png"  width="49%" height="auto">
</p>
<br>
<hr>

#### Alert View
Quickly find evil on your network with Suricata IDS paired with the [Emerging Threats Rule Sets](https://rules.emergingthreats.net/).
<p float="left">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-suricata-alerts.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-suricata-threats.png"  width="49%" height="auto">
</p>
<br>
<hr>

#### Baseline Network Assets
Understand the normal behavior of assets on your network; gain insight into what is anomalous.

<p float="left">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-baselines-overview.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-baselines2.png"  width="49%" height="auto">
</p>
<br>
<hr>

#### Monitor Statistics
Easily track agents and NetFlow devices forwarding traffic to DynamiteNSM.
<p float="left">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-stats-overview.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-stats-zeek.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-stats-suricata.png"  width="49%" height="auto">
</p>

### Dynamite Lab
Install JupyterHub alongside our custom SDK, and explore your data inside Jupyter Notebooks.
<p float="left">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-lab-startup.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-lab-tutorials.png"  width="49%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-lab-notebook-open.png"  width="49%" height="auto">
</p>

### Install, Manage, and Scale
Easily add new agents and monitoring components into your environment through intuitive installation.
<p float="left">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-lab-install.png"  width="30%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-agent-install.png"  width="64%" height="auto">
</p>

Configure components without ever having to interact with a configuration file.
<p float="left">
<img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-zeek-configure.png"  width="22%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-zeek-script.configure.png"  width="36%" height="auto">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/screenshots/dynamite-nsm-suricata-rules-configure.png"  width="34%" height="auto">
</p>


### Getting Started

While there are quite a few components that are a part of Dynamite-NSM. Standing up a standalone agent/monitor deployment is very simple.

Check to see if your operating system is [supported](SUPPORTED_OSs.md).

#### Monitor (Standalone all components installed)

##### Specs
```
Linux Kernel: 2.6.32+
14 GB of RAM at least 4 vCPU
```

##### Installation

Grab the the release, and install.

```bash
python setup.py install
```

Install the monitoring components all on the same machine.
```bash
dynamite install monitor
```

Start the monitor. The Kibana UI can be found at: http://localhost:5601
```bash
dynamite start monitor
```

You can login with the `elastic` user and the password you set during installation.

#### Agent

##### Specs
```
Linux Kernel: 2.6.32+
8+ GB of RAM at least 4 vCPU
```

##### Installation

Grab the the release, and install.

```bash
python setup.py install
```

Prepare the agent, this installs any required kernel-headers needed to install the PF_RING kernel module. 

```bash
dynamite prepare agent
```

Reboot, and install the agent. This process can take between 10 and 40 minutes depending on your specs.

```bash
dynamite install agent --interface mon01 --agent-label honeypot1 --ls-host <logstash-host> --ls-port 5044
```

Start the agent
```bash
dynamite start agent
```

If you need to point the agent to a new monitor, this can be accomplished using the below command.

```bash
dynamite point agent --ls-host <new-logstash-host> --ls-port 5044
```


### Additional Usage

In addition to being able to stand up the monitor as a single instance (ElasticSearch, Logstash, and Kibana all installed) 
This tool can also be used to install these components separately.

Check out the advanced guide [here](https://github.com/vlabsio/dynamite-nsm/tree/master/scripts/README.md).
