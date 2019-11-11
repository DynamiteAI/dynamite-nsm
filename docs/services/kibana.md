# dynamite_nsm.services.kibana

## KibanaAPIConfigurator
```python
KibanaAPIConfigurator(self, configuration_directory='/etc/dynamite/kibana/')
```

Provides an interface for interacting with the Kibana APIs

### create_elastiflow_saved_objects
```python
KibanaAPIConfigurator.create_elastiflow_saved_objects(self, stdout=False)
```

Creates ElastiFlow dashboards, visualizations, and searches

- *param* stdout: Print output to console
- *return* True, if created successfully

## KibanaConfigurator
```python
KibanaConfigurator(self, configuration_directory='/etc/dynamite/kibana/')
```

Wrapper for configuring kibana.yml

### get_server_host
```python
KibanaConfigurator.get_server_host(self)
```

- *return* The host the Kibana is running on

### get_server_port
```python
KibanaConfigurator.get_server_port(self)
```

- *return* The port the Kibana is running on

### get_elasticsearch_hosts
```python
KibanaConfigurator.get_elasticsearch_hosts(self)
```

- *return* A list of elasticsearch hosts to connect too

### get_elasticsearch_password
```python
KibanaConfigurator.get_elasticsearch_password(self)
```

- *return* The password to the ElasticSearch 'kibana' user

### set_server_host
```python
KibanaConfigurator.set_server_host(self, host='0.0.0.0')
```

- *param* host: The IP address for Kibana service to listen on

### set_server_port
```python
KibanaConfigurator.set_server_port(self, port=5601)
```

- *param* port: The port number of the for Kibana service to listen on

### set_elasticsearch_hosts
```python
KibanaConfigurator.set_elasticsearch_hosts(self, host_list)
```

- *param* host_list: A list of ElasticSearch hosts for Kibana to connect too

### set_elasticsearch_password
```python
KibanaConfigurator.set_elasticsearch_password(self, password)
```

- *param* password: The ElasticSearch password for the 'kibana' user

### write_configs
```python
KibanaConfigurator.write_configs(self)
```

Write (and backs-up) kibana.yml configuration

## KibanaInstaller
```python
KibanaInstaller(self, host='0.0.0.0', port=5601, elasticsearch_host=None, elasticsearch_port=None, elasticsearch_password='changeme', install_directory='/opt/dynamite/kibana/', configuration_directory='/etc/dynamite/kibana/', log_directory='/var/log/dynamite/kibana/')
```

Provides a simple interface for installing a new Kibana interface with ElastiFlow dashboards

### download_kibana
```python
KibanaInstaller.download_kibana(stdout=False)
```

Download Kibana archive

- *param* stdout: Print output to console

### extract_kibana
```python
KibanaInstaller.extract_kibana(stdout=False)
```

Extract Kibana to local install_cache

- *param* stdout: Print output to console

### setup_kibana
```python
KibanaInstaller.setup_kibana(self, stdout=False)
```

Create required directories, files, and variables to run ElasticSearch successfully;

- *param* stdout: Print output to console

## KibanaProfiler
```python
KibanaProfiler(self, stderr=False)
```

Interface for determining whether Kibana is installed/configured/running properly.

## KibanaProcess
```python
KibanaProcess(self)
```

An interface for start|stop|status|restart of the Kibana process

### start
```python
KibanaProcess.start(self, stdout=False)
```

Start the Kibana process

- *param* stdout: Print output to console
- *return* True, if started successfully

### stop
```python
KibanaProcess.stop(self, stdout=False)
```

Stop the Kibana process

- *param* stdout: Print output to console
- *return* True if stopped successfully

### restart
```python
KibanaProcess.restart(self, stdout=False)
```

Restart the Kibana process

- *param* stdout: Print output to console
- *return* True if started successfully

### status
```python
KibanaProcess.status(self)
```

Check the status of the ElasticSearch process

- *return* A dictionary containing the run status and relevant configuration options

## install_kibana
```python
install_kibana(elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme', install_jdk=True, create_dynamite_user=True, stdout=False)
```

Install Kibana/ElastiFlow Dashboards

- *param* elasticsearch_host: A hostname/IP of the target elasticsearch instance
- *param* elasticsearch_port: A port number for the target elasticsearch instance
- *param* elasticsearch_password: The password used for authentication across all builtin ES users
- *param* install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
- *param* create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run
Logstash/ElasticSearch/Kibana
- *param* stdout: Print the output to console
- *return* True, if installation succeeded

## uninstall_kibana
```python
uninstall_kibana(stdout=False, prompt_user=True)
```

Uninstall Kibana/ElastiFlow Dashboards

- *param* stdout: Print the output to console
- *param* prompt_user: Print a warning before continuing
- *return* True, if uninstall succeeded

