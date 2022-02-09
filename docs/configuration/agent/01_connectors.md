# Connectors

> ⚠️ Changes made within these interfaces require that Filebeat be restarted. Typically, the easiest way to 
> accomplish this is via the command:
> `sudo dynamite filebeat process restart`

Dynamite `agents` rely on `filebeat` for sending events and alerts to a downstream collector. The following are currently supported.

- Logstash
- Elasticsearch (default)
- Redis
- Kafka

## Logstash

```bash
dynamite filebeat config logstash_targets -h
```

Logstash is powerful data-processing pipeline by Elastic.co. It provides a versatile set of configuration driven ingestion, filtering, and transformation functions. Logstash can be paired with a multitude of upstream retention solutions such as ElasticSearch and InfluxDB.

| Option Name        | Description                                                                                                                            | Example                             |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| Host/Ports      | A comma delimited list of `host:port` pairs. This list represents where to send the logs.                                           | localhost:5044, logstash-2-box:5044 |
| Proxy URL       | The URL of the SOCKS5 proxy to use when connecting to the Logstash servers. The value must be a URL with a scheme of   `socks5://.` | socks5://192.168.0.55:1080          |
| Index Name      | The index root name to write events to.                                                                                             | dynamite_events-%{+yyyy.MM.dd}      |
| Async Pipelines | Configures the number of batches to be sent asynchronously to Logstash while waiting for ACK from Logstash.                         | 2                                   |
| Max Batch Size  | The maximum number of events to bulk in a single LogStash request.                                                                  | 2048                                |

## ElasticSearch

```bash
sudo dynamite filebeat config elasticsearch_targets -h
```

Elasticsearch is a search engine by Elastic.co that provides distributed, full-text search and supports retention of schemaless data. Elasticsearch is often deployed behind one or more Logstash instances, however in this configuration ingestion is achieved by directly connecting to Elasticsearch's index API.

| Option Name   | Description                                                                                  | Example                             |
|------------|-------------------------------------------------------------------------------------------|-------------------------------------|
| Host/Ports | A comma delimited list of `host:port` pairs. This list represents where to send the logs. | localhost:9200, elastic-02-box:9200 |
| Index Name | The index name to write events to when you’re using daily indices.                        | dynamite_events-%{+yyyy.MM.dd}      |
| Username   | The basic authentication username for connecting to Elasticsearch.                        | elastic                             |
| Password   | The basic authentication password for connecting to ElasticSearch.                        | ¡my_$ecure_p@ssw0rd!                |

## Kafka

```bash
sudo dynamite filebeat config kafka_targets -h
```

Apache Kafka is a distributed event streaming platform and brokering solution providing high-performance data pipelines for realtime feeds. If extremely high volumes of network traffic are expected, Kafka is a good option.

| Option Name   | Description                                                                                                                            | Example                             |
|------------|-----------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| Host/Ports | A comma delimited list of `host:port` pairs. This list represents where to send the logs.                                               | localhost:5044, logstash-2-box:5044 |
| Topic      | The Kafka topic used for produced events.                                                                                               | dynamite_events                     |
| Username   | The username for connecting to Kafka. If username is configured, the password must be configured as well. Only SASL/PLAIN is supported. | dynamite_pub                        |
| Password   | The password for connecting to Kafka.                                                                                                   | ¡my_$ecure_p@ssw0rd!                |

## Redis

```bash
sudo dynamite filebeat config redis_targets -h
```

Redis is an open source, in-memory data structure store, used as a database, cache, and message broker. If your goal is short-lived visualizations of realtime network analytics, Redis is a great fit.

| Option Name       | Description                                                                                                                                                                                                                                  | Example                             |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| Host/Ports     | A comma delimited list of `host:port` pairs. This list represents where to send the logs.                                                                                                                                                | localhost:5044, logstash-2-box:5044 |
| Proxy URL      | The URL of the SOCKS5 proxy to use when connecting to the Logstash servers. The value must be a URL with a scheme of   `socks5://.`                                                                                                      | socks5://192.168.0.55:1080          |
| Workers        | The number of workers to use for each host configured to publish events to Redis. Use this setting along with the load-balance option. For example, if you have 2 hosts and 3 workers, in total 6 workers are started (3 for each host). | 2                                   |
| Load Balancing | If set to `true` and multiple hosts or workers are configured, the output plugin load balances published events onto all Redis hosts.                                                                                                    | true                                |
| Max Batch Size | The maximum number of events to bulk in a single Redis request or pipeline.                                                                                                                                                              | 2048                                |
| Db             | The Redis database number where the events are published.                                                                                                                                                                                | 0                                   |
| Password       | The password to authenticate with. The default is no authentication.                                                                                                                                                                     | ¡my_$ecure_p@ssw0rd!                |

