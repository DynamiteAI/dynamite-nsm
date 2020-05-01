# Event Dashboards


![Event Dashboards](../img/dashboards/gifs/event-dashboards.gif)

The event module is the heart of DynamiteNSM, originally forked from [ElastiFlow](https://github.com/robcowart/elastiflow) this module is meant to provide a central place for a variety of network relationships. These dashboards work both with our agent and NetFlow exporters. They can be broken down into the following categories:

  - **Top-N or Top-Talkers**: Quickly discover relationships about the chattiest hosts on (or off) your network. Get insight into the service protocols they are using.
  - **Flows or Events**: Gain insights on high-level conversations. Who are my clients vs. servers?
  - **Geographical**: Where in the world is my traffic coming from? Where is it going?
  - **Autonomous Systems**: Information about traffic from public IP ranges.
  - **Traffic Details**: Discover additional relationships in your traffic like IP protocol versions and source/destination VLANs.
  - **Flow Records**: View the original network events.