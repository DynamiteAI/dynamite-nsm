# Agent Deployment Considerations

Agents are responsible for monitoring traffic on a network interface(s), performing some initial analysis, and forwarding them on to a LogStash collector.

This document provides general guidance for designing and building appliances to serve as Dynamite Agents.  The intent is to be able to leverage commodity hardware at a minimal cost while enabling maximum performance at the target network traffic inspection rates.  

> Note that while these recommendations apply to physical appliances the specifications below can also be used as a reference for creating virtual machines to serve as Agents and Monitors, however, the target traffic inspection rates are generally lower due to many performance limiting factors involved in the hypervisors use and emulation of hardware.  If creating a virtual server to act as a Dynamite Agent, consider using PCIe passthrough to assign physical NICs to the agent VM.  This serves to bypass some of the hypervisor overhead, offering maximum traffic inspection performance from a SPAN, tap or packet aggregation device.

### CPUs

Choosing the right CPUs can have a major impact on overall system performance.  Intel Xeon processors are recommended with the following attributes:

- Minimum 2.1GHz 
- Minimum 4 cores
- Hyper Threading Enabled
- \> 10MB L3 cache 
- Sandy Bridge Microarchitecture or newer

#### General Guidelines

| Agent Size | Max Sustained Throughput | CPU/Cores | Threads |
|------------|--------------------------|-----------|---------|
| Mini       | 500 Mbps                 | 8         | 16      |
| Small      | 1 Gbps                   | 16        | 32      |
| Medium     | 6 Gbps                   | 36        | 72      |
| Large      | 12 Gbps                  | 72        | 144     |

### Memory (RAM)

As with CPU, the type and amount of RAM heavily influence system performance.  The following best-practices should be considered when selecting RAM for use in Dynamite Agents or Monitors:

- Use fast memory 
- Use minimal DIMMs, e.g. 8x 16GB vs 16x 8GB
- Evenly distribute DIMMs per socket

#### General Guidelines

| Agent Size | Max Sustained Throughput | RAM (GB) |
|------------|--------------------------|----------|
| Mini       | 500 Mbps                 | 32       |
| Small      | 1 Gbps                   | 64       |
| Medium     | 6 Gbps                   | 320      |
| Large      | 12 Gbps                  | 512      |

### Inspection Network Interfaces

The type of network interface card (NIC) heavily influences the agent’s ability to efficiently capture and process packets.  Dynamite recommends the following NIC models for use as traffic inspection interfaces as they have well-maintained drivers with the feature sets needed for tuning:  

- Intel X550
- Intel X710
- Mellanox


### OS Drives

To avoid I/O contention and ensure data storage consumption does not affect the OS’s ability to function, Dynamite recommends creating a separate storage volume exclusively for use by the OS.

The OS storage volume should be configured with:

- SSD drives for fast I/O, the same make/model
- RAID 1 for full data redundancy 

### Data Drives

A separate data storage volume should be created to maximize write performance and alleviate I/O contention with the OS.  Creating a separate data volume also helps ensure storage consumption will not adversely affect OS operation.  

The data storage volume should be configured with: 

- 10K RPM HDD or SSD (higher I/O but fewer possible read/write operations over lifespan)
- All drives the same make/model
- RAID 0 for fast I/O 

#### General Guidelines

| Agent Size | Max Sustained Throughput | Data Storage (TB) |
|------------|--------------------------|-------------------|
| Mini       | 500 Mbps                 | 1                 |
| Small      | 1 Gbps                   | 2                 |
| Medium     | 6 Gbps                   | 8                 |
| Large      | 12 Gbps                  | 16                |

