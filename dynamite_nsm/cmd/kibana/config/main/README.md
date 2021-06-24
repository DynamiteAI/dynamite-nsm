```bash
usage: [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--verbose] [--stdout] [--out-file-path OUT_FILE_PATH] [--backup-directory BACKUP_DIRECTORY] [--top-text TOP_TEXT] [--host HOST] [--port PORT] [--elasticsearch-targets ELASTICSEARCH_TARGETS [ELASTICSEARCH_TARGETS ...]]
            [--elasticsearch-username ELASTICSEARCH_USERNAME] [--elasticsearch-password ELASTICSEARCH_PASSWORD] [--kibana-config-path KIBANA_CONFIG_PATH]

Kibana Configuration - Configure Kibana on this machine.

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        Path to the configuration directory (E.G /etc/dynamite/kibana/)
  --verbose             Include detailed debug messages
  --stdout              Print output to console
  --out-file-path OUT_FILE_PATH
                        The path to the output file; if none given overwrites existing
  --backup-directory BACKUP_DIRECTORY
                        The path to the backup directory
  --top-text TOP_TEXT   The text to be appended at the top of the config file (typically used for YAML version header)

configuration options:
  --host HOST
  --port PORT
  --elasticsearch-targets ELASTICSEARCH_TARGETS [ELASTICSEARCH_TARGETS ...]
  --elasticsearch-username ELASTICSEARCH_USERNAME
  --elasticsearch-password ELASTICSEARCH_PASSWORD
  --kibana-config-path KIBANA_CONFIG_PATH
```