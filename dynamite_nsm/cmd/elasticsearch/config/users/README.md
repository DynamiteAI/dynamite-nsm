```bash
usage: [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--verbose] [--stdout] [--out-file-path OUT_FILE_PATH] [--backup-directory BACKUP_DIRECTORY] [--top-text TOP_TEXT] [--node-name NODE_NAME] [--cluster-name CLUSTER_NAME] [--seed-hosts SEED_HOSTS [SEED_HOSTS ...]]
            [--initial-master-nodes INITIAL_MASTER_NODES [INITIAL_MASTER_NODES ...]] [--network-host NETWORK_HOST] [--http-port HTTP_PORT] [--path-logs PATH_LOGS] [--search-max-buckets SEARCH_MAX_BUCKETS] [--rest-api-pem-cert-file REST_API_PEM_CERT_FILE] [--rest-api-pem-key-file REST_API_PEM_KEY_FILE]
            [--rest-api-trusted-cas-file REST_API_TRUSTED_CAS_FILE] [--transport-pem-cert-file TRANSPORT_PEM_CERT_FILE] [--transport-pem-key-file TRANSPORT_PEM_KEY_FILE] [--transport-trusted-cas-file TRANSPORT_TRUSTED_CAS_FILE]
            [--authcz-admin-distinguished-names AUTHCZ_ADMIN_DISTINGUISHED_NAMES [AUTHCZ_ADMIN_DISTINGUISHED_NAMES ...]] [--elasticsearch-config-path ELASTICSEARCH_CONFIG_PATH]

Elasticsearch Configuration - Configure Elasticsearch on this machine.

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        Path to the configuration directory (E.G /etc/dynamite/elasticsearch/)
  --verbose             Include detailed debug messages
  --stdout              Print output to console
  --out-file-path OUT_FILE_PATH
                        The path to the output file; if none given overwrites existing
  --backup-directory BACKUP_DIRECTORY
                        The path to the backup directory
  --top-text TOP_TEXT   The text to be appended at the top of the config file (typically used for YAML version header)

configuration options:
  --node-name NODE_NAME
  --cluster-name CLUSTER_NAME
  --seed-hosts SEED_HOSTS [SEED_HOSTS ...]
  --initial-master-nodes INITIAL_MASTER_NODES [INITIAL_MASTER_NODES ...]
  --network-host NETWORK_HOST
  --http-port HTTP_PORT
  --path-logs PATH_LOGS
  --search-max-buckets SEARCH_MAX_BUCKETS
  --rest-api-pem-cert-file REST_API_PEM_CERT_FILE
  --rest-api-pem-key-file REST_API_PEM_KEY_FILE
  --rest-api-trusted-cas-file REST_API_TRUSTED_CAS_FILE
  --transport-pem-cert-file TRANSPORT_PEM_CERT_FILE
  --transport-pem-key-file TRANSPORT_PEM_KEY_FILE
  --transport-trusted-cas-file TRANSPORT_TRUSTED_CAS_FILE
  --authcz-admin-distinguished-names AUTHCZ_ADMIN_DISTINGUISHED_NAMES [AUTHCZ_ADMIN_DISTINGUISHED_NAMES ...]
  --elasticsearch-config-path ELASTICSEARCH_CONFIG_PATH

```