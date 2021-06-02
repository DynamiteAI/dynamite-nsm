# Elasticsearch

Elasticsearch is a distributed, open-source search and analytics engine built on Apache Lucene and developed in Java.
Within DynamiteNSM it is used to store all network events and alerts that have been acquired and normalized by the agent.

DynamiteNSM pre-configures Elasticsearch with several useful defaults, and automatically optimizes its use of the JVM heap.

## Installation
```bash
sudo dynamite elasticsearch install -h
```

## Configuration
```markdown
sudo dynamite elasticsearch config -h
```

## Process Management
```markdown
sudo dynamite elasticsearch process -h
```

## Defaults

### Directories

- Configuration Directory: `/etc/dynamite/elasticsearch/`
- Installation Directory:  `/opt/dynamite/elasticsearch/`
- Logs: `/var/log/dynamite/elasticsearch/`
- JAVA_HOME: `/usr/lib/jvm//jdk-13.0.1`

### Access


- API URL: `https://<management-ip>:9200`
- Default User: `admin`
- Default Password: `admin`
