# Quick Start

This document will walk you through getting DynamiteNSM up in running in a small environment.
This setup will work with small lab environments, but is not suggested for scenarios where over 300MiBs of sustained throughput is expected.

## Pre-requisites

- Two physical or virtual machines running a [supported operating system](/supported_operating_systems). One machine will be dedicated to packet acquisition and analysis - **The Agent**; the other for the storing and presentation of this data - **The Monitor**.

| Role    | RAM | CPUs | Network Interfaces  |
|---------|-----|------|---------------------|
| Monitor | 8   | 4    | 1                   |
| Agent   | 32   | 8    | 2                  |

> ⓘ For the sake of testing your RAM and CPU can be decreased below the above small-network recommendation,
> however this may result in dropped packets depending on your average throughput.

> ⓘ `dynamite zeek logs metrics --pretty` and `dynamite suricata logs metrics --pretty` can be used to watch for dropped packets.


- A physical or virtual switch capable of [SPANing or a dedicated TAP](/requirements/04_span_vs_tap) device.
- [Python 3.7+](https://www.python.org/downloads/).


## Setup DynamiteNSM SDKs and utilities.

- Install DynamiteNSM libraries and command-line utilities.

```bash
pip install dynamite-nsm
```

- Download any default configuration or mirror updates.
```bash
sudo dynamite updates install
```

## Install the Monitor

The monitor consists of the services which receive network events/alerts from the agent(s), and normalize/visualize 
them in ways that can be useful for security and operational use-cases.

- **On your first computer, that you will use for monitoring,** run the below command.

```bash
sudo dynamite monitor install
```

- Once installed, you may start the monitor.

```bash
sudo dynamite monitor process start
```

- Verify services are running.

```bash
sudo dynamite monitor process status
```

```
╒═══════════════╤═════════╤════════════════════╕
│ Service       │ Running │ Enabled on Startup │
├───────────────┼─────────┼────────────────────┤
│ kibana        │ yes     │ yes                │
├───────────────┼─────────┼────────────────────┤
│ elasticsearch │ yes     │ yes                │
╘═══════════════╧═════════╧════════════════════╛
```

- Log into Elasticsearch/Kibana. The default credentials for both are `admin/admin`. 
   Be sure to select the `global` tenant when prompted, as we install several default dashboards and visualizations to this space.
> ⓘ Note that you it takes time to start these services. You may get connection timeouts initially. 

You can access `elasticsearch` and `kibana` at the below URLs.

| Monitor Tool  | URL                            |
|---------------|--------------------------------|
| Elasticsearch | `https://<management_ip>:9200` |
| Kibana        | `http://<management_ip>:5601`  |


## Install the Agent

The agent is responsible for acquiring network packets off one or more SPAN/TAP interface and distilling these packets into meaningful 
events and alerts that can be sent to a Dynamite Monitor or supported collector.

- On the computer dedicated to packet acquisition determine which network interface you wish to use to monitor traffic. 
   `ifconfig` and `ip addr` are useful commands for enumerating the interfaces you have available.

- Begin the agent installation

```bash
sudo dynamite agent install --target-type=elasticsearch --targets=https://<monitor-ip-address>:9200 --inspect-interfaces=<mon_iface0> <mon_iface1>
```

- Start the agent.

```bash
sudo dynamite agent process start
```

- Confirm the agent is running as expected

```bash
sudo dynamite agent process status
```

```
╒══════════╤═════════╤════════════════════╕
│ Service  │ Running │ Enabled on Startup │
├──────────┼─────────┼────────────────────┤
│ filebeat │ yes     │ yes                │
├──────────┼─────────┼────────────────────┤
│ zeek     │ yes     │ yes                │
├──────────┼─────────┼────────────────────┤
│ suricata │ yes     │ yes                │
╘══════════╧═════════╧════════════════════╛
```

- Confirm that we were able to connect to Elasticsearch

```bash
sudo dynamite filebeat logs main --pretty
```

```
╒════════════════════════════╤═══════════╤═══════════════════════════╤════════════════════════════════════════════════════════════════════════════════╕
│ Time                       │ Log Level │ Category                  │ Message                                                                        │
├────────────────────────────┼───────────┼───────────────────────────┼────────────────────────────────────────────────────────────────────────────────┤
│ 2021-04-25 17:06:50.780000 │ INFO      │ publisher_pipeline_output │ Connection to backoff(elasticsearch(https://192.168.194.143:9200)) established │
╘════════════════════════════╧═══════════╧═══════════════════════════╧════════════════════════════════════════════════════════════════════════════════╛
```

- If you ever change the hardware specifications or wish to monitor an additional network interface be sure to run the below command, which will automatically recalibrate `zeek` and `suricata` for efficient resource utilization.

```bash
sudo dynamite agent optimize --inspect-interfaces=<mon_iface0> <mon_iface1>
```