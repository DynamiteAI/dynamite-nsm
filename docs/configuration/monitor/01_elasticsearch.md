# Elasticsearch

> ⚠️ Changes made within these interfaces require that Elasticsearch be restarted. Typically, the easiest way to 
> accomplish this is via the command:
> `sudo dynamite elasticsearch process restart`

DynamiteNSM exposes two configurations specific to Elasticsearch: `java` and `main`.

1. The `java` configuration allows users to automatically adjust the `heap_space` allocated to Elasticsearch.
2. The `main` configuration provides limited access into several relevant sections of the `elasticsearch.yaml`.

## Java

To display current `java` options.

```bash
sudo dynamite elasticsearch config java
```

```markdown
╒════════════════╤═══════╕
│ Config Option  │ Value │
├────────────────┼───────┤
│ initial_memory │ 8g    │
├────────────────┼───────┤
│ maximum_memory │ 8g    │
╘════════════════╧═══════╛
```

To update Elasticsearch's allocated heap-space:

```bash
sudo dynamite elasticsearch config java --initial-memory 12g --maximum-memory 12g
```

## Main

To display the current `main` configuration options.

```bash
sudo dynamite elasticsearch config main
```

```markdown
╒══════════════════════════════════╤════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╕
│ Config Option                    │ Value                                                                                                              │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ node_name                        │ dyna_dev_es_node                                                                                                   │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ cluster_name                     │ dynamite-nsm-cluster                                                                                               │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ seed_hosts                       │ ['192.168.194.143']                                                                                                │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ initial_master_nodes             │ ['jamindev_es_node']                                                                                               │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ network_host                     │ 192.168.194.143                                                                                                    │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ http_port                        │ 9200                                                                                                               │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ path_logs                        │ /var/log/dynamite/elasticsearch/                                                                                   │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ search_max_buckets               │ 10000                                                                                                              │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ rest_api_pem_cert_file           │ security/auth/admin.pem                                                                                            │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ rest_api_pem_key_file            │ security/auth/admin-key.pem                                                                                        │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ rest_api_trusted_cas_file        │ security/auth/root-ca.pem                                                                                          │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ transport_pem_cert_file          │ security/auth/admin.pem                                                                                            │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ transport_pem_key_file           │ security/auth/admin-key.pem                                                                                        │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ transport_trusted_cas_file       │ security/auth/root-ca.pem                                                                                          │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ authcz_admin_distinguished_names │ ['C=US,ST=GA,L=Atlanta,O=Dynamite,OU=R&D,CN=dynamite.ai', 'CN=dynamite.ai,OU=R&D,O=Dynamite,L=Atlanta,ST=GA,C=US'] │
├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ elasticsearch_config_path        │ /etc/dynamite/elasticsearch//elasticsearch.yml                                                                     │
╘══════════════════════════════════╧════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╛
```

Two update one or more configuration values:

```bash
sudo dynamite elasticsearch config main --http-port 8080 --search-max-buckets 15000
```