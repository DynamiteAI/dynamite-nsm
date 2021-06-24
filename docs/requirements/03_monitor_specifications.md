# Monitor Deployment Considerations

Monitors combine Elasticsearch, and Kibana into a single instance, and receive traffic from the agents. 

> ⓘ Logstash is not installed by default, however it is available for installation 
> as a separate component via: `dynamite logstash install -h`. Manual configuration is required to further integrate
> Logstash with a Dynamite monitor instance.



## Data Drives

A separate data storage volume should be created to maximize write performance and alleviate I/O contention with the OS.  Creating a separate data volume also helps ensure storage consumption will not adversely affect OS operation.  

The data storage volume should be configured with:
- 10K RPM HDD or SSD (higher I/O but fewer possible read/write operations over lifespan)
- All drives the same make/model
- RAID 0 for fast I/O 

## CPUs

Most operations within Elasticsearch are CPU bound, and there are many variables beyond `events-per-second` that contribute to load.
The following options are a good starting place when benchmarking your monitor.

| Events per Second | CPUs/Cores |
|-------------------|------------|
| 250               | 4          |
| 1000              | 8          |
| 2500              | 12         |

## Memory & Disk

Elasticsearch is built upon Lucene data-structures which require large `HashMaps` remain in memory at all time.
Depending on the size of your indices, query operations can become very expensive. The following are a good place to start.

> ⓘ To avoid I/O contention and ensure data storage consumption does not affect the OS’s ability to function, Dynamite recommends creating a separate storage volume exclusively for use by the OS.
> The OS storage volume should be configured with:

> - SSD drives for fast I/O, the same make/model
> - RAID 1 for full data redundancy


| Events per Second | RAM (GB) | Disk (30-days) | Elasticsearch JVM Heap |
|-------------------|----------|----------------|------------------------|
| 250               | 24       | 305 GB         | 8 GB                   |
| 1000              | 32       | 1.22 TB        | 12 GB                  |
| 2500              | 64       | 3.05 TB        | 24 GB                  |

