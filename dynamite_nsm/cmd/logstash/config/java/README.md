```bash
usage: [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--verbose] [--stdout] [--out-file-path OUT_FILE_PATH] [--backup-directory BACKUP_DIRECTORY] [--logstash-jvm-config-path LOGSTASH_JVM_CONFIG_PATH] [--initial-memory INITIAL_MEMORY] [--maximum-memory MAXIMUM_MEMORY]

Logstash Java Heap Configuration - Configure Java heap allocation for Logstash on this machine.

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

configuration options:
  --logstash-jvm-config-path LOGSTASH_JVM_CONFIG_PATH
  --initial-memory INITIAL_MEMORY
  --maximum-memory MAXIMUM_MEMORY

```
