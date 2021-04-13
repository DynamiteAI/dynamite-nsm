## About

Passive network monitoring is an approach to network monitoring where traffic is "sniffed" via
strategically placed sensors on critical junctions of your network. DynamiteNSM aims to make the process of setting up
the sensor and monitoring infrastructure needed to collect and make sense of this data as seamless as possible.

DynamiteNSM was built around several design goals to make it an attractive alternative to heavier weight NSMs.

1. **Minimal-knowledge Deployment**: A user should be able to get to a working state with minimal or 
   no documentation.
2. **Intelligent Defaults**: A user is not required to understand the intricacies of our stack to start running with 
   reasonable configurations.
3. **Unified Utility for Management**: All the tools for installing, managing, and monitoring Dynamite services should 
   be accessible in a single utility. 
4. **SDKs for Everything**: Every installable service in the DynamiteNSM can be controlled through a set of Python 
   libraries. Users should always have the option of building their own interfaces to manage these services.
5. **Extremely Customizable**: A user should be able to customize DynamiteNSM to fit a variety of operational, 
   threat-hunting, and detection use-cases.
   
## Services

### Agent Services


The agent (sensor) is responsible for generating JSON events from raw network packets and forwarding these events to a monitor. 

| Component   | Description                                                                                                                                                                                                                                                      |
|-------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Zeek [3.0.3]](https://github.com/zeek/zeek)           | Previously Bro, Zeek is a powerful network analysis framework that is differs from your typical IDS. It is capable of enumerating detailed information surrounding network connections and their underlying protocols.|
| [Suricata [4.1.4]](https://github.com/OISF/suricata)   | Suricata is an Intrusion Detection System (IDS), powered by the latest open [EmergingThreat](https://doc.emergingthreats.net/) rule-sets.
| [Oinkmaster [2.0]](http://oinkmaster.sourceforge.net/download.shtml)| A script to automate management of Suricata rule-sets, and keep rules up-to-date.
| [Filebeat [7.2.1]](https://github.com/elastic/beats)   | A powerful log forwarder, with a built in queue mechanisms, and a pressure sensitive protocol that works in conjunction with LogStash.                                                                                |


### Monitor Services

The monitor is responsible for collecting these events, enriching and normalizing them, and presenting them to the end-user through intuitive visualizations and a powerful search user interface

| Component                                              | Description                                                                                                                     |
|--------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| [Logstash [7.2.1]](https://github.com/elastic/logstash)            | A server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it. |
| [Elasticsearch [7.2.0]](https://github.com/elastic/elasticsearch)  | A distributed, RESTful search and analytics engine.                                                                 |
| [Kibana [7.2.0]](https://github.com/elastic/kibana)                | A web-app that allows you to visualize your Elasticsearch data     