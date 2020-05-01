<a href="http://dynamite.ai"><img src="https://github.com/vlabsio/dynamite-nsm/raw/master/img/dynamite-analytics.png" width="350" height="auto"></a>


## Dynamite Network Security Monitor

[Dynamite-NSM](http://dynamite.ai) is a free Network Security Monitor (NSM), built on top of several leading, enterprise-grade technologies. The tool provides network and cybersecurity operators with holistic insights into their networks while giving them the ability to deep-dive into lower-level activities.

- The solution presents powerful dashboards, giving comprehensive view into performance and threat-based metrics. Dynamite-NSM can be easily deployed in different environments including high-speed data centers, small-to-large enterprises, IoT & industrial networks, and even at home.

- Handles massive volumes of network traffic through scalable ingestion and optimized network sensors. The solution includes two key components: the agent and the monitor. The agent analyzes and forwards network events, while the monitor processes incoming events and displays analytic information.

- Builds upon the ElasticStack (ElasticSearch, LogStash, Kibana) and is coupled with the fine-tuned Zeek sensor (aka Bro), flow data inputs (NetFlow, sFlow, IPFIX), and Suricata IDS security alerts. Dynamite-NSM now includes the DynamiteLab component made of the python API for easy data access and integrated JupyterHub hosted notebooks as the data science environment. 

- Designed to be deployed very quickly with minimal configuration. Unlike many other tools, it can be installed and managed with a standalone command-line utility. The system is inherently passive without disruption to the network. There is no need to install agents on every computer, perform network scans, or directly interact with network assets. To start receiving analytics, we just connect agents and optional flow sources to the monitor.

- Installed and managed through a commandline utility implemented in pure Python.

<p align="center">
    <hr>
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/0.7.0_refactor/img/architechture-demo.gif"  width="90%" height="auto">
    <hr>
    <b font-size=3><i style="color:grey">Installation examples are accelerated for the sake of demo.</i></b>
</p>

## Install With

```bash
pip install dynamite-nsm
```

## Documentation

- [About](https://dynamite-nsm.readthedocs.io/en/latest/)
- [Introduction](https://dynamite-nsm.readthedocs.io/en/latest/introduction/)
- [Getting Started](https://dynamite-nsm.readthedocs.io/en/latest/getting_started/)
  - [Prerequisites](https://dynamite-nsm.readthedocs.io/en/latest/getting_started/prerequisites/)
  - [Agent Setup](https://dynamite-nsm.readthedocs.io/en/latest/getting_started/agent_setup/)
  - [Monitor Setup](https://dynamite-nsm.readthedocs.io/en/latest/getting_started/monitor_setup/)
- [Kibana Dashboards](https://dynamite-nsm.readthedocs.io/en/latest/kibana_dashboards/)
- [DynamiteLab <sub>Experimental</sub>](https://dynamite-nsm.readthedocs.io/en/latest/dynamite_lab/)








