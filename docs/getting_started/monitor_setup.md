# Setting up the Monitor

The DynamiteNSM Monitor is responsible for ingestion, normalization, and presentation of of network data.

## Deployment Types

You can deploy the monitor in one of two ways:

1. Single instance monitor deployment - All components are installed on the same machine.
2. Split instance monitor deployment - Components are installed on separate machines.

Determining which option best suits your needs depends on your traffic volume and available hardware. Be sure to check out our [deployment considerations](../introduction/deployment_considerations.md) before making a decision which route to take.

### Single Instance Monitor Deployment

To install the Monitor on a single instance, simply ensure that you have at least 16GB of RAM and 4 vCPUs. 

Set the heap-space for both LogStash and ElasticSearch to below `8GB` total `(available RAM / 2)`.

```
[root@sensor]$ dynamite monitor install --es-heap-size=5 --ls-heap-size=3
```

### Split Instance Monitor Deployment

To install the Monitor across multiple instances install ElasticSearch first, and point LogStash and Kibana to them once installation is complete.

Install ElasticSearch on `Machine_A`:

```
[root@sensor]$ dynamite elasticsearch install --es-heap-size=16
```

Install LogStash on `Machine_B`

```
[root@sensor]$ dynamite logstash install --ls-heap-size=16 --es-host=Machine_A --es-port=9200
```

And Install Kibana on `Machine_C`

```
[root@sensor]$ dynamite kibana install --es-host=Machine_A --es-port=9200
```

## Validating your Deployment

```
[root@sensor] dynamite monitor status
```

Relevant logs default locations are listed below, and are useful for troubleshooting.

- Elasticsearch - `/var/dynamite/elasticsearch/dynamite-cluster.log`
- Logstash - `/var/dynamite/logstash/logstash-plain.log`
- Kibana - `/var/log/dynamite/kibana/kibana.log`

Once started relevant services will listen on the following addresses (unless overridden during installation):

| Application                 | URL                   | Username |
|-----------------------------|-----------------------|----------|
| Elasticsearch               | http://localhost:9200 | elastic  |
| Kibana                      | http://localhost:5601 | elastic  |
| Logstash (Agent Pipeline)   | tcp://localhost:5044  | N/A      |
| Logstash (NetFlow Pipeline) | tcp://localhost:2055  | N/A      |

> Be sure that any firewall rules have been created to allow the above services to be accessible. 

> If you open up any of the Kibana dashboards and are greeted with errors, know that this is expected behavior when no events have been received yet. 
