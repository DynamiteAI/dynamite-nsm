```bash
usage:  [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--verbose] [--stdout] [--out-file-path OUT_FILE_PATH] [--backup-directory BACKUP_DIRECTORY] [--top-text TOP_TEXT] [--node-name NODE_NAME] [--path-data PATH_DATA] [--path-logs PATH_LOGS] [--pipeline-batch-size PIPELINE_BATCH_SIZE]
        [--pipeline-batch-delay PIPELINE_BATCH_DELAY] [--logstash-config-path LOGSTASH_CONFIG_PATH]

Logstash Configuration - Configure Logstash on this machine.

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        Path to the configuration directory (E.G /etc/dynamite/logstash/)
  --verbose             Include detailed debug messages
  --stdout              Print output to console
  --out-file-path OUT_FILE_PATH
                        The path to the output file; if none given overwrites existing
  --backup-directory BACKUP_DIRECTORY
                        The path to the backup directory
  --top-text TOP_TEXT   The text to be appended at the top of the config file (typically used for YAML version header)

configuration options:
  --node-name NODE_NAME
  --path-data PATH_DATA
  --path-logs PATH_LOGS
  --pipeline-batch-size PIPELINE_BATCH_SIZE
  --pipeline-batch-delay PIPELINE_BATCH_DELAY
  --logstash-config-path LOGSTASH_CONFIG_PATH
```