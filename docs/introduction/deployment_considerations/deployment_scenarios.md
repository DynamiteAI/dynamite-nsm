# Deployment Scenarios

## Terminology

- **Sensor** - The physical (or virtual) computer that the agent runs on.
- **Agent** - A software component which is part of DynamiteNSM, it consists of several analyzer modules and a forwarder module.
- **Monitor** - A software component which is part of DynamiteNSM, it consists of several ingest, normalization, and visualisation modules.

Deployment can be broken down into two super categories:

1. Agent Deployment Strategies
2. Monitor Deployment Strategies


## Agent Deployment Strategies

To be able to start forwarding events an agent must be deployed on a **span port** or a **network tap**. Both have their advantages and disadvantages. 

- A **span port** (Switch Port Analyzer), is a feature provided by most managed switches, essentially a device is plugged into this span port. 

- A **network tap** (Test Access Point) a dedicated device that transmit both the send and receive data streams simultaneously on separate channels. They are deployed in-line and are a single point of failure. Be careful when choosing a network tap!


### Spans vs Taps

<p align="center">
<img src="../../../img/span.png" width="200" height="auto">
<font size=5>  VS  </font>
<img src="../../../img/tap.png" width="200" height="auto">
</p>

#### Span Ports
- Available on almost all managed switches
- Does not sit inline, if the span port fails, it will not disrupt network connectivity.
- Remotely configurable

#### Network Taps
- A high quality tap typically handles much better under high traffic load (will not drop packets.)
- Court admissible and provides forensically sound data/evidence.
- Have no IP address and no MAC address and are not vulnerable to conventional network attacks.


At the end of the day, network taps usually emerge as the best option, but span ports are a very reasonable alternative if you expect low-medium levels of traffic or do not care especially about dropped packets.

### Where do I put my sensors?

This largely depends on the goals of your network monitoring program. 

A couple of rules of thumb:

- One sensor per network segment.
- Avoid deploying on a centralized hub.
- Sensors must be able to talk back to monitor.

## Monitor Deployment Strategies

The DynamiteNSM Monitor is a collection of applications and configurations bundled together into a single service. At the heart of the monitor is the ElasticStack: ElasticSearch, LogStash, and Kibana. The nature of ElasticSearch, is to scale. As your monitoring requirements expand, so too will your ElasticSearch cluster.

### Single-Instance Monitor

If you are monitoring rather low volumes of traffic, and have a sensor with at least 16GB of RAM and 4 vCPUs you can deploy a single instance monitor node.

```bash
dynamite monitor install --ls-heap-size=3 --es-heap-size=5
```

The above command will install a single-instance monitor on your selected hardware.

### Split-Instance Monitor

LogStash and ElasticSearch can be memory hogs, and a single-instance monitor should not be considered on machines with over 64GB of RAM or those ingesting **2,500** events per second. Instead, split the monitor into it's multiple components.

Install ElasticSearch on `Machine_A`:

```bash
dynamite elasticsearch install --es-heap-size=16
```

Install LogStash on `Machine_B`

```bash
dynamite logstash install --ls-heap-size=16 --es-host=Machine_A --es-port=9200
```

And Install Kibana on `Machine_C`

```bash
dynamite kibana install --es-host=Machine_A --es-port=9200
```

#### Add new ElasticSearch Nodes
In addition, you can install additional ElasticSearch nodes and join them to your cluster. Simply copy the `elastic-certificates.p12` certificate from `/etc/dynamite/elasticsearch/config/` into the same folder on each new node.