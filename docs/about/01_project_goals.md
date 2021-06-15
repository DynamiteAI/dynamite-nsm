# Project Goals

Passive network monitoring is an approach to network monitoring where traffic is *sniffed* via
strategically placed sensors on critical junctions of your network. DynamiteNSM aims to make the process of setting up
the sensor and monitoring infrastructure needed to collect and make sense of this data as seamless as possible.

DynamiteNSM was built around several design goals to make it an attractive alternative to heavier weight NSMs.

## Lightweight and Extensible

Give users the choice as to which services they want to download and install without the need of installing a dedicated operating system.

Services should be self-contained, provide multiple integration paths, and be easy to extend.

## Flexible

Give users the ability to customize DynamiteNSM to fit a variety of operational, detection, and threat-hunting use-cases.

Users should be able to extend functionality of DynamiteNSM through packages that encapsulate dashboards, visualizations and internal configurations.

## Secure

Wherever possible services should be installed with security in mind. 

By default, all services must use encrypted channels of communication and require authentication. 

## Intelligent Defaults
Where possible provide intelligent defaults. Users should not need to understand the intricacies of DynamiteNSM to start running with 
reasonable configurations. 

Intelligently configure installed services to best utilize system resources where possible; provide overrides for these defaults.

## Minimal Knowledge Deployment
Provide rich contextual help menus and intuitive interfaces wherever possible. Keep interfaces simple.

Users should be able to get to a working state with minimal to no documentation.

## Remote Management

Provide users with the tools needed to remotely manage DynamiteNSM nodes.

Users should be able to control nodes and perform operations against multiple nodes at once. Users should be able 
to copy the configuration state of one node to another.

   
