***Discover your network***
<a href="http://dynamite.ai"><img src="https://github.com/vlabsio/dynamite-nsm/raw/master/img/dynamite-logo.png" width="350" height="auto"></a>
## Dynamite Network Security Monitor
<!--- ### ***Discover your network*** --->
[DynamiteNSM](http://dynamite.ai) is a free Network Security Monitor (NSM), built on top of several leading, enterprise-grade technologies. The tool provides network and cybersecurity operators with holistic insights into their networks while giving them the ability to deep-dive into lower-level activities.

### Why DynamiteNSM?
- ***Start monitoring your network in minutes.*** Let DynamiteNSM handle all the complexities of setting up *Zeek*, *Suricata*, and *ElasticStack*. 
- ***Manage through a single commandline utility***. DynamiteNSM is written in Python, and provides a single [commandline](https://github.com/DynamiteAI/dynamite-nsm/tree/master/scripts) utility for managing all the components of the NSM.
- ***Handle massive volumes of network traffic.*** DynamiteNSM will automatically detect the best agent configuration for your environment. 
- ***Deploy in a variety of environments.*** DynamiteNSM can be easily deployed in different environments including high-speed data centers, small-to-large enterprises, IoT & industrial networks, and even at home.
- ***Discover your network through powerful Kibana Dashboards.*** DynamiteNSM presents powerful dashboards, giving comprehensive view into performance and threat-based metrics. 
- ***Explore your network in JupyterNotebooks.*** DynmiateNSM includes the `lab` component which integrates our SDK with JupyterHub environment, an incredibly powerful way to explore your network.
- ***"The quieter you become, the more you can hear."*** DynamiteNSM is inherently passive and works without disruption to the network. 

<p align="center"float="center">
    <img src="https://github.com/DynamiteAI/dynamite-nsm/raw/master/img/architechture-demo.gif"  width="90%" height="auto">
    <br>
    <i style="color:grey">Installation examples are accelerated for the sake of demo.</i>
</p>

### Documentation
Want to learn how to install DynamiteNSM in your own environment?
Check out the [ReadTheDocs](https://dynamite-nsm.readthedocs.io/en/stable/).

### Installation

DynamiteNSM has been extensively tested on the following [Linux distributions](https://dynamite-nsm.readthedocs.io/en/stable/introduction/supported_operating_systems/).

Packages are available for `Python2.7+.`
```bash
pip install dynamite-nsm
```

### External Configurations

DynamiteNSM depends heavily on a set of default configurations that are updated in parallel with every release.

Dynamite hosts these configurations iin a publically accessible S3 bucket, and the utility will check this location to retrieve the latest configs and mirrors.

***Optionally***, you can host your own configurations/mirrors for custom deployments.

- https://github.com/DynamiteAI/dynamite-nsm-configurations


### Feedback
Let us know what you think! We're constantly looking to improve our software.
- <a href="https://form.asana.com?hash=8ba73263c69e9e1669984cd54c2a53f5cc3912fc3f97ebdf8a1236fe5895563f&id=1174202259248192"><img src="https://github.com/vlabsio/dynamite-nsm/raw/master/img/bug.png" width="20" height="auto"> Report a Bug</a>

- <a href="https://form.asana.com?hash=ab1ed5270731e938e5e19386e526c1dd7aba912ffc1a2dbd2ca18855cebbd08f&id=1174344134673446"><img src="https://github.com/vlabsio/dynamite-nsm/raw/master/img/story.png" width="20" height="auto"> Request a Feature</a>
