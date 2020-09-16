# About
### *DISCOVER YOUR NETWORK*

DynamiteNSM is a free Network Security Monitor developed by Dynamite Analytics to enable network visibility and advanced cyber threat detection. The tool provides network and cybersecurity operators with holistic insights into their networks while giving them the ability to deep-dive into lower-level activities.
The solution presents powerful dashboards, giving comprehensive view into performance and threat-based metrics. Dynamite-NSM can be easily deployed in different environments including high-speed data centers, small-to-large enterprises, IoT & industrial networks, and even at home.

DynamiteNSM handles massive volumes of network traffic through scalable ingestion and optimized network sensors. The solution includes two key components: the agent and the monitor. The agent analyzes and forwards network events, while the monitor processes incoming events and displays analytic information.

The monitor component builds upon the ELK stack (ElasticSearch, LogStash, Kibana) and is coupled with the fine-tuned Zeek sensor (aka Bro), flow data inputs (NetFlow, sFlow, IPFIX), and Suricata IDS security alerts. Dynamite-NSM now includes the DynamiteLab component made of the python API for easy data access and integrated JupyterHub hosted notebooks as the data science environment.

DynamiteNSM is designed to be deployed very quickly with minimal configuration. Unlike many other tools, it can be installed and managed with a standalone command-line utility. The system is inherently passive without disruption to the network. There is no need to install agents on every computer, perform network scans, or directly interact with network assets. To start receiving analytics, we just connect agents and optional flow sources to the monitor.

DynamiteNSM can be installed and managed through a commandline utility implemented in pure Python.

No need to download a huge ISO image or install a dedicated operating system!
