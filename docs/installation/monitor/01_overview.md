# Overview

The monitor refers to the services required for retention, querying, and presentation. The monitor will install
Elasticsearch and Kibana. 

>⚠️ Logstash, is an optional component that can be installed separately, however we currently don't provide an automated integration strategy with Logstash.
> Meaning, if you wish to have agents forward to Logstash, you will need to create your own input and output pipelines.


<p align="center">
    <img src="/data/img/arch_monitor.png"/>
</p>

1. **Install Elasticsearch and Kibana on the same physical instance.** This is the simplest option, and in most situations the best one.
Use these [hardware guidelines](/requirements/03_monitor_specifications) as a starting place.

2. **Install Elasticsearch and Kibana on separate instances.** Setup Elasticsearch for authentication to Kibana. This might be a good option
if you want Elasticsearch running in a different network segment.  