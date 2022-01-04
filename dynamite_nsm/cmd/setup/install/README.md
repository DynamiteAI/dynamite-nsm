

```bash
$ sudo python3 install_logstash/ -h
usage:  [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--install-directory INSTALL_DIRECTORY] [--log-directory LOG_DIRECTORY] [--download-logstash-archive] [--stdout] [--verbose] [--node-name NODE_NAME] [--host HOST] [--elasticsearch-host ELASTICSEARCH_HOST] [--elasticsearch-port ELASTICSEARCH_PORT]
        [--pipeline-batch-size PIPELINE_BATCH_SIZE] [--pipeline-batch-delay PIPELINE_BATCH_DELAY] [--heap-size-gigs HEAP_SIZE_GIGS]

Logstash - None

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        Path to the configuration directory (E.G /etc/dynamite/logstash/)
  --install-directory INSTALL_DIRECTORY
                        Path to the install directory (E.G /opt/dynamite/logstash/)
  --log-directory LOG_DIRECTORY
                        Path to the log directory (E.G /var/log/dynamite/logstash/)
  --download-logstash-archive
                        If True, download the Logstash archive from a mirror
  --stdout              Print output to console
  --verbose             Include detailed debug messages
  --node-name NODE_NAME
  --host HOST
  --elasticsearch-host ELASTICSEARCH_HOST
  --elasticsearch-port ELASTICSEARCH_PORT
  --pipeline-batch-size PIPELINE_BATCH_SIZE
  --pipeline-batch-delay PIPELINE_BATCH_DELAY
  --heap-size-gigs HEAP_SIZE_GIGS
```