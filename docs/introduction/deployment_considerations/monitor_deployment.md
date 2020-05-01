# Monitor Deployment Considerations

Monitors combine LogStash, ElasticSearch, and Kibana into a single instance, and receive traffic from the agents.

This document provides general guidelines for designing and building appliances to serve as Dynamite Monitors.

### Single-Instance vs Split-Instance Deployment

For anything beyond **2,500** events per second, a multi-node cluster should be considered, and that LogStash should be run on its own instance/server.


### CPUs

| Events per Second | CPUs/Cores |
|-------------------|------------|
| 250               | 4          |
| 1000              | 8          |
| 2500              | 12         |


### Memory/Disk/Heap

| Events per Second | RAM (GB) | Disk (30-days) | ES JVM Heap | LS JVM Heap |
|-------------------|----------|----------------|-------------|-------------|
| 250               | 24       | 305 GB         | 8 GB        | 4 GB        |
| 1000              | 32       | 1.22 TB        | 12 GB       | 4 GB        |
| 2500              | 64       | 3.05 TB        | 24 GB       | 6 GB        |


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
