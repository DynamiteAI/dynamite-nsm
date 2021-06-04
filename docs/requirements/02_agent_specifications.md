# Agent Specifications

## CPUs

Choosing the right CPUs can have a major impact on overall system performance.
> ⓘ CPU considerations

> - Minimum 2.1GHz
> - Hyper Threading Enabled
> - At least 10MB L3 cache 
> - Sandy Bridge Microarchitecture or newer

| Agent Size | Max Sustained Throughput | CPU/Cores | Threads |
|------------|--------------------------|-----------|---------|
| Mini       | 500 Mbps                 | 8         | 16      |
| Small      | 1 Gbps                   | 16        | 32      |
| Medium     | 6 Gbps                   | 36        | 72      |
| Large      | 12 Gbps                  | 72        | 144     |

## Memory

As with CPU, the type and amount of RAM heavily influence system performance. The following best-practices should be 
considered when selecting RAM for use in Dynamite Agents or Monitors.

> ⓘ Memory considerations

> - Use fast memory
> - Use minimal DIMMs, e.g. 8x 16GB vs 16x 8GB
> - Evenly distribute DIMMs per socket

| Agent Size | Max Sustained Throughput | RAM (GB) |
|------------|--------------------------|----------|
| Mini       | 500 Mbps                 | 32       |
| Small      | 1 Gbps                   | 64       |
| Medium     | 6 Gbps                   | 320      |
| Large      | 12 Gbps                  | 512      |

## Network Inspection Interfaces


The type of network interface card (NIC) heavily influences the agent’s ability to efficiently capture and process packets. Dynamite recommends the following NIC models for use as traffic inspection interfaces as they have well-maintained drivers with the feature sets needed for tuning:  

- Intel X550
- Intel X710
- Mellanox

## Data Drives

A separate data storage volume should be created to maximize write performance and alleviate I/O contention with the OS.  Creating a separate data volume also helps ensure storage consumption will not adversely affect OS operation.  

The data storage volume should be configured with: 

> ⓘ HDD considerations

> - 10K RPM HDD or SSD (higher I/O but fewer possible read/write operations over lifespan)
> - All drives the same make/model
> - RAID 0 for fast I/O

| Agent Size | Max Sustained Throughput | Data Storage (TB) |
|------------|--------------------------|-------------------|
| Mini       | 500 Mbps                 | 1                 |
| Small      | 1 Gbps                   | 2                 |
| Medium     | 6 Gbps                   | 8                 |
| Large      | 12 Gbps                  | 16                |