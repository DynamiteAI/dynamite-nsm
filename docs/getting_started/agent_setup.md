# Setting up the Agent

![Agent Setup](../img/gifs/agent-install.gif)

## Prerequisites

There are a few things you need to do before you can install the agent.

### 1. Enable Promiscuous Mode

Configure the network interface you wish to monitor to run in promiscuous mode. In the below examples `[monitor_interface]` represents the name of the interface you want to monitor (E.G `mon0`).

```
[root@sensor]$ ifconfig [monitor_interface] promisc
```

**OR**

```
[root@sensor]$ ip link set [monitor_interface] promisc on
```

**To validate:**

```
[root@sensor]$ ifconfig [monitor_interface] | grep PROMISC
```

**OR**

```
[root@sensor]$ ip a show eth1 | grep -i promisc
```

*Note that these settings will not persist past reboot, you will need to research the best way to persist promiscuous mode for your selected distribution.*

### 2. Install Kernel Development Headers

You will also need to install the Kernel Development Headers for your distribution. DynamiteNSM makes this easy.

```
[root@sensor]$ dynamite agent-dependencies install
```

When prompted, reboot.

## Agent Installation

Pick the scenario that makes the most sense for your goals.

### Scenario 1

- Install Agent
     - with Zeek and Suricata enabled 
     - monitoring a single network interface 
     - and forward to a single Monitor/LogStash instance.

```
[root@sensor]$ dynamite agent install --analyzers zeek suricata --capture-interface mon0 --targets upstream_monitor.mynet.local:5044
```

### Scenario 2

- Install Agent
    - with Just Zeek enabled
    - monitoring multiple interfaces
    - and forwarding to multiple Monitor/LogStash instances
  
```
[root@sensor]$ dynamite agent install --analyzers zeek  --capture-interface mon0 mon1 mon2 --targets upstream_monitor1.mynet.local:5044 upstream_monitor2.mynet.local:5044
```

### Scenario 3

- Install Agent
    - with Just Suricata enabled
    - monitoring multiple interfaces
    - and forwarding to multiple Kafka brokers
    

```
[root@sensor]$ dynamite agent install --analyzers suricata  --capture-interface mon0 mon1 mon2 --targets upstream_monitor1.mynet.local:9092 upstream_monitor2.mynet.local:9092 --kafka-topic dynamite-events
```

### Scenario 4

- Install Agent
    - with Just Zeek and Suricata enabled
    - monitoring multiple interfaces
    - and forwarding to multiple Kafka brokers
    - that require authentication
    
```
[root@sensor]$ dynamite agent install --analyzers zeek suricata  --capture-interface mon0 mon1 mon2 --targets upstream_monitor1.mynet.local:9092 upstream_monitor2.mynet.local:9092 --kafka-topic dynamite-events --kafka-password=changeme --kafka-user=jaminbecker
```

## Validating the Agent Installation

Once installed run `dynamite agent status` to validate all components installed correctly.

If they did you can start the agent.

```
dynamite agent start
```

Relevant logs are:

- Zeek Current Log Directory: `/opt/dynamite/zeek/logs/current/`
- Suricata Log Directory `/var/log/dynamite/suricata/`
- Filebeat Log: `/opt/dynamite/filebeat/logs/filebeat`