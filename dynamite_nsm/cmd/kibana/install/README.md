```bash
usage: [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--install-directory INSTALL_DIRECTORY] [--log-directory LOG_DIRECTORY] [--download-kibana-archive] [--stdout] [--verbose] [--host HOST] [--port PORT] [--elasticsearch-targets ELASTICSEARCH_TARGETS [ELASTICSEARCH_TARGETS ...]]

Kibana Install - Install Kibana as a standalone component.

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        Path to the configuration directory (E.G /etc/dynamite/kibana/)
  --install-directory INSTALL_DIRECTORY
                        Path to the install directory (E.G /opt/dynamite/kibana/)
  --log-directory LOG_DIRECTORY
                        Path to the log directory (E.G /var/log/dynamite/kibana/)
  --download-kibana-archive
                        If True, download the Kibana archive from a mirror
  --stdout              Print output to console
  --verbose             Include detailed debug messages
  --host HOST           The IP or hostname to listen on
  --port PORT           The port to listen on
  --elasticsearch-targets ELASTICSEARCH_TARGETS [ELASTICSEARCH_TARGETS ...]
                        A list of Elasticsearch urls

```