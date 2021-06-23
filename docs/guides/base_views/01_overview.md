# Overview

**By default**, DynamiteNSM ships with a powerful analytics package containing dashboards and visualizations purpose built for a variety 
of operational and detection use-cases. 


## Modules

Within the `BaseViews` Kibana package, `modules` designate a collection of views built around a specific sub-set of filters.

These filters slice Dynamite's [ECS based](/about/data_model/01_overview) data into four categories: alerts, events, and hosts, and protocols. 

Each module provides a unique perspective into one of these categories.

### Alerts

Alerts are typically indicative of behavior suspicious or malicious behavior. 

> ⓘ You can always [adjust](/configuration/agent/03_scripts_and_rules#suricata) the kinds of alerts that get triggered through the dynamite commandline utility.

<p align="center">
    <img src="/data/img/kibana_dashboard_alerts.png" />
</p>

### Conversations

Conversations are bi-directional communication between hosts. 
In addition to conversations this view provides some high-level summaries of top-talkers, top-recipients, and application
protocol metrics.

<p align="center">
    <img src="/data/img/kibana_dashboard_conversations.png" />
</p>

### Hosts

The host views focus on providing metrics from the perspective of internal and external hosts on and off the network.

<p align="center">
    <img src="/data/img/kibana_dashboard_hosts.png" />
</p>

### Protocols

Protocols in this module refer primarily to application layer protocols. 
This view primarily functions as a launch point into protocol specific views.

> ⓘ You can always [adjust](/configuration/agent/03_scripts_and_rules#zeek) the kinds of protocols that get analyzed through the dynamite commandline utility.


<p align="center">
    <img src="/data/img/kibana_dashboard_protocols.png" />
</p>

