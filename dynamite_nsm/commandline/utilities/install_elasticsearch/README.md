```bash
$ sudo python3 install_elasticsearch/ -h
usage: install_elasticsearch [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--install-directory INSTALL_DIRECTORY] [--log-directory LOG_DIRECTORY] [--download-elasticsearch-archive] [--stdout] [--verbose] [--node-name NODE_NAME] [--network-host NETWORK_HOST] [--port PORT]
                             [--initial-master-nodes INITIAL_MASTER_NODES [INITIAL_MASTER_NODES ...]] [--discover-seed-hosts DISCOVER_SEED_HOSTS [DISCOVER_SEED_HOSTS ...]] [--tls-cert-subject TLS_CERT_SUBJECT] [--heap-size-gigs HEAP_SIZE_GIGS]

Elasticsearch - Install Elasticsearch as a standalone component.

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
  --install-directory INSTALL_DIRECTORY
                        Path to the install directory (E.G /opt/dynamite/elasticsearch/)
  --log-directory LOG_DIRECTORY
                        Path to the log directory (E.G /var/log/dynamite/elasticsearch/)
  --download-elasticsearch-archive
                        If True, download the ElasticSearch archive from a mirror
  --stdout              Print output to console
  --verbose             Include detailed debug messages
  --node-name NODE_NAME
                        The name of this elasticsearch node
  --network-host NETWORK_HOST
                        The IP address to listen on (E.G "0.0.0.0")
  --port PORT           The port that the ES API is bound to (E.G 9200)
  --initial-master-nodes INITIAL_MASTER_NODES [INITIAL_MASTER_NODES ...]
                        A list of nodes representing master (and master-eligible) nodes in this cluster
  --discover-seed-hosts DISCOVER_SEED_HOSTS [DISCOVER_SEED_HOSTS ...]
                        A list of IPs on other hosts you wish to form a cluster with
  --tls-cert-subject TLS_CERT_SUBJECT
                        Denotes the thing being secured; E.G (/C=US/ST=GA/L=Atlanta/O=Dynamite Analytics/OU=R&D/CN=dynamite.ai)
  --heap-size-gigs HEAP_SIZE_GIGS
                        The initial/max java heap space to allocate

```