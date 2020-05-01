# Project Goals

**Easy to install, maintain, and scale**

One of the major downsides to Zeek is its complexity to deploy, difficulty to scale, and inability to natively forward logs to a centralized solution. The tool should provide a methodology for aggregating events from a variety of sources, normalizing them, and presenting them intelligently to the end-user.


**Comprehensible and useful network visualisations**

Network data is vast and often incomprehensible, finding what is relevant is often like trying to find a needle in a haystack. The tool should provide a set of customizable visualisations that are useful regardless of network volume.

**Hybrid Netflow and Zeek deployments**

The solution should provide a methodology for normalizing events from both Netflow devices and Zeek based agents (sensors). In addition, it should provide visualizations and dashboards for these representing these events to the end-user.


**Baseline analytics that scale with your network**

In the simplest sense, baselining begins with taking time-interval snapshots and aggregating these around one or more metrics, such as IP address. The team quickly realized that this process lends itself to scalability issues. The more events ingested, the more computationally expensive these aggregations become. The solution should provide a scalable methodology that allows time-intervals to be captured and aggregated without crippling the hardware.


**JupyterHub Integration to explore their network data**

ElasticSearch and Kibana allow end-users to explore their data in a variety of ways. However, these are limited to a finite number of visualizations and metrics operations. For advanced users, the solution should provide an extendable framework for programmatically exploring data. It should allow users to interact directly with the backend data-models.

**Open-source and easy to contribute to!**

The tool should provide an easy path for code contribution. Code should be well documented, and community resources made available to encourage contribution.