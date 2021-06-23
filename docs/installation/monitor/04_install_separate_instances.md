# Install across Separate Instances

In some situations, such as a multi-node Elasticsearch deployment, you may not always wish
to install Elasticsearch or Kibana separately.

## Update Default Configs and Mirrors

On each instance make sure you have the latest default configurations and mirrors for the version of DynamiteNSM you have installed.
```bash
sudo dynamite updates install
```

## Dedicated Elasticsearch Instance

By default, Elasticsearch will bind itself to the primary IP address, this can be overridden with the `--network-host`
flag.

### Install Elasticsearch Service

```bash
sudo dynamite elasticsearch install
```
### Start the Process

Once installed, you can manage Elasticsearch with the process command.

```bash
sudo dynamite elasticsearch process start
sudo dynamite elasticsearch process status --verbose
```


## Dedicated Kibana Instance

### Test the Connection to Elasticsearch

Before you begin the Kibana installation ensure that Elasticsearch API is up and reachable from whatever
host you want to install Kibana on.

```bash
curl https://192.168.194.143:9200 -u admin:admin --insecure
```

You should receive a message similar to the one below:

```json5
{
  "name" : "ip1723021417_es_node",
  "cluster_name" : "dynamite-nsm-cluster",
  "cluster_uuid" : "GIUvsLdlRb-WyQD5j3kd6Q",
  "version" : {
    "number" : "7.10.2",
    "build_flavor" : "oss",
    "build_type" : "tar",
    "build_hash" : "747e1cc71def077253878a59143c1f785afa92b9",
    "build_date" : "2021-01-13T00:42:12.435326Z",
    "build_snapshot" : false,
    "lucene_version" : "8.7.0",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
```

Now simply run the `dynamite kibana install` command specifying any `--elasticsearch-targets`. As with `elasticsearch` you can
override the bound IP address with the `--host` flag.

### Install Kibana Service

```bash
sudo dynamite kibana install --elasticsearch-targets https://192.168.194.143:9200
```

### Start the Process

Once installed, you can manage Kibana with the process command.

```bash
sudo dynamite kibana process start
sudo dynamite kibana process status --verbose
```