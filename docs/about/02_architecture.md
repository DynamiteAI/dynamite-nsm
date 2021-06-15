# General Architecture

Within DynamiteNSM a `service` is a collection of wrappers around a utility that provide the ability to perform actions like:

- installation
- configuration
- process management
- performance monitoring
- troubleshooting

Services can be grouped together into components. There are two primary components: the [Agent](/services/03_agent) and the [Monitor](/services/02_monitor).

Agents run on dedicated hardware that inspects mirrored traffic and forwards logs on to a [downstream collector](/configuration/agent/01_connectors). 
The monitor is Dynamite's solution for indexing and presenting network events and insights forwarded from agents in a way useful to security analysts and threat hunters.

The Dynamite team also developed a very simple remote management utility called [dynamite-remote](https://github.com/DynamiteAI/utilities/tree/master/dynamite-remote) that allows administrators remotely manage 
[remote](/services/10_remote) enabled instances. 

![](../data/img/dynamite_arch.png)

### Agent Services


The agent (sensor) is responsible for generating JSON events from raw network packets and forwarding these events to a monitor. 

![](../data/img/arch_agent.png)

| Service                           | Project Link                               | Version | Description                                                                                                                                                                                                    | License                                                                                  |
|-----------------------------------|--------------------------------------------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| [Zeek](/services/07_zeek)         | [Github](https://github.com/zeek/zeek)     | 3.0.3   | Zeek (formerly Bro) is a free and open-source software network analysis framework. It provides an extremely powerful scripting language that can be used for everything from protocol parsing to file carving. | [BSD](https://github.com/zeek/zeek/blob/master/COPYING)                                  |
| [Suricata](/services/08_suricata) | [Github](https://github.com/OISF/suricata) | 4.1.4   | Suricata is an Intrusion Detection System (IDS), powered by the latest open [EmergingThreat](https://doc.emergingthreats.net/) rule-sets.                                                                      | [GPL 2.0](https://github.com/OISF/suricata/blob/master/LICENSE)                          |
| [Filebeat](services/filebeat)     | [Github](https://github.com/elastic/beats) | 7.11.1  | Filebeat-OSS is a free and open-source log shipper written in GoLang. The utility is capable of forwarding logs to a variety of destination types.                                                             | [Apache 2.0](https://github.com/elastic/beats/blob/7.12/licenses/APACHE-LICENSE-2.0.txt) |

### Monitor Services

The monitor is responsible for collecting these events, enriching and normalizing them, and presenting them to the end-user through intuitive visualizations and a powerful search user interface

![](../data/img/arch_monitor.png)

| Services                                    | Project Link                                              | Version                                                                        | Description                                                                                                         | License                                                                                       |
|---------------------------------------------|-----------------------------------------------------------|--------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| [Logstash](/services/05_logstash)           | [Github](https://github.com/elastic/logstash)             | 7.11.1                                                                         | A server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it. | [Apache 2.0](https://github.com/elastic/logstash/blob/master/licenses/APACHE-LICENSE-2.0.txt) |
| [Elasticsearch](/services/04_elasticsearch) | [Github](https://opendistro.github.io/for-elasticsearch/) | [1.13.0](https://opendistro.github.io/for-elasticsearch-docs/version-history/) | A distributed, RESTful search and analytics engine.                                                                 | [Apache 2.0](https://aws.github.io/)                                                          |
| [Kibana](/services/06_kibana)               | [Github](https://opendistro.github.io/for-elasticsearch/) | [1.13.0](https://opendistro.github.io/for-elasticsearch-docs/version-history/) | A web-app that allows you to visualize your Elasticsearch data                                                      | [Apache 2.0](https://aws.github.io/)                                                          |