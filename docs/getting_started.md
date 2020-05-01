# Getting Started

Determining the best way to deploy DynamiteNSM depends largely on what you want to monitor. As a general rule, if you are monitoring more than a few machines you should consider deploying the monitoring components on dedicated hardware. Practically speaking this means install Logstash, Elasticsearch, and Kibana each on their own instance.

If you, however, do not expect above 2,500 events-per-second then installing the above components on a single-instance monitor is perfectly acceptable.

Either way, carefully read through the [deployment considerations](../introduction/deployment_considerations) guide before continuing.


## Additional Reading
 - [Prerequisites](getting_started/prerequisites.md)
 - [Commandline Installation](getting_started/cmd_installation.md)
 - [Commandline Overview](getting_started/cmd_overview.md)
 - [Agent Setup](getting_started/agent_setup.md)
 - [Monitor Setup](getting_started/monitor_setup.md)