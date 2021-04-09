## Description
This document will walk you through installing DynamiteNSM agent and monitor components on the same physical instance.
This setup will work with small lab environments, but is not suggested for larger deployment scenarios.

## Requirements

- One [Linux Instance](/supported_operating_systems) with at least 16 GB of RAM and 8 cores.
- At least two network interfaces attached to the above interface. One for management, one for receiving monitor traffic.
- A physical or virtual switch with SPAN capabilities.
- `Python 3.8` or higher
- `apt-get` or `yum` package manager installed


## Prepare your Linux Instance
In order to function properly you will need to provision at least two network interfaces on this instance: one for 
management and one for receiving monitor traffic (sniffing).

Be sure to check out the examples in our [network configuration](/network_interface_configuration) documentation.

## Setup DynamiteNSM

1. Install DynamiteNSM libraries and command-line utilities.

```bash
pip3 install dynamite-nsm==1.0.0
```

2. Download any default configuration or mirror updates.
```bash
sudo dynamite updates install
```

3. Install the **OpenDistro Elasticsearch** for data retention.

```bash
sudo dynamite elasticsearch install
```

4. Install **OpenDistro Kibana** for data visualisation.
```bash
sudo dynamite kibana install
```

5. Install **Zeek** for network metadata collection.
```bash
sudo dynamite zeek install --network-capture-interface=mon0
```

6. Install **Suricata** for suspicious network alerts
```bash
sudo dynamite suricata install --network-capture-interfaces=mon0
```

## Start the Monitor

The monitor consists of the components which receive traffic from the agent(s) and normalize and visualize them in ways
that can be useful for security and operational use-cases.

1. Start **OpenDistro Elasticsearch**.
```bash
dynamite elasticsearch process start
```
2. Confirm that it is running
```bash
dynamite elasticsearch process status --verbose
```

3. Start **OpenDistro Kibana**
```bash
dynamite kibana process start
```
4. Confirm that it is running
```bash
dynamite kibana process status --verbose
```

## Start the Agent

1. Start **Zeek**.
```bash
dynamite zeek process start
```
2. Confirm that it is running
```bash
dynamite zeek process status --verbose
```
3. Start **Suricata**
```bash
dynamite suricata process start
```
4. Confirm that it is running
```bash
dynamite suricata process status --verbose
```
5. Start **Filebeat-OSS**
```bash
dynamite filebeat process start
```
6. Confirm that it is running
```bash
dynamite filebeat process status --verbose

## Viewing your Data

After a few minutes network traffic from your monitoring interface should start showing up in the `filebeat-*` index
within Elasticsearch.

You can start exploring your data at one of the URLs below with the credentials ***admin/admin***:

| Monitor Tool  | URL                            |
|---------------|--------------------------------|
| Elasticsearch | `https://<management_ip>:9200` |
| Kibana        | `https://<management_ip>:5601` |