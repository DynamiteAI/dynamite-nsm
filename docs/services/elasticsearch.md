# dynamite_nsm.services.elasticsearch

## ElasticConfigurator
```python
ElasticConfigurator(self, configuration_directory)
```

Wrapper for configuring elasticsearch.yml and jvm.options

### get_cluster_name
```python
ElasticConfigurator.get_cluster_name(self)
```

- *return* The name of the ElasticSearch cluster

### get_network_host
```python
ElasticConfigurator.get_network_host(self)
```

- *return* The server that the cluster is running on

### get_network_port
```python
ElasticConfigurator.get_network_port(self)
```

- *return* The port that the cluster is running on

### get_node_name
```python
ElasticConfigurator.get_node_name(self)
```

- *return* The name of the ElasticSearch node

### get_data_path
```python
ElasticConfigurator.get_data_path(self)
```

- *return* The directory where data is being stored

### get_log_path
```python
ElasticConfigurator.get_log_path(self)
```

- *return* The directory logs are being stored in

### get_discovery_seed_hosts
```python
ElasticConfigurator.get_discovery_seed_hosts(self)
```

- *return* A list of hosts also in the cluster

### get_jvm_initial_memory
```python
ElasticConfigurator.get_jvm_initial_memory(self)
```

- *return* The initial amount of memory the JVM heap allocates

### get_jvm_maximum_memory
```python
ElasticConfigurator.get_jvm_maximum_memory(self)
```

- *return* The maximum amount of memory the JVM heap allocates

### set_cluster_name
```python
ElasticConfigurator.set_cluster_name(self, name)
```

- *param:* name: The name of the cluster

### set_network_host
```python
ElasticConfigurator.set_network_host(self, host='localhost')
```

- *param:* host: The IP address for ElasticSearch service to listen on

### set_network_port
```python
ElasticConfigurator.set_network_port(self, port=9200)
```

- *param:* port: The port number of the for ElasticSearch service to listen on

### set_node_name
```python
ElasticConfigurator.set_node_name(self, name)
```

- *param:* name: The name of the ElasticSearch node

### set_data_path
```python
ElasticConfigurator.set_data_path(self, path)
```

- *param:* path: The path to the ElasticSearch node data

### set_log_path
```python
ElasticConfigurator.set_log_path(self, path)
```

- *param:* path: The path to the log directory

### set_discovery_seed_host
```python
ElasticConfigurator.set_discovery_seed_host(self, host_list)
```

- *param:* host_list: A list of hosts also in the cluster

### set_jvm_initial_memory
```python
ElasticConfigurator.set_jvm_initial_memory(self, gigs)
```

- *param:* gigs: The amount of initial memory (In Gigabytes) for the JVM to allocate to the heap

### set_jvm_maximum_memory
```python
ElasticConfigurator.set_jvm_maximum_memory(self, gigs)
```

- *param:* gigs: The amount of maximum memory (In Gigabytes) for the JVM to allocate to the heap

### write_configs
```python
ElasticConfigurator.write_configs(self)
```

Write (and backs-up) elasticsearch.yml and jvm.option configurations

## ElasticPasswordConfigurator
```python
ElasticPasswordConfigurator(self, auth_user, current_password)
```

Provides a basic interface for resetting ElasticSearch passwords

### set_apm_system_password
```python
ElasticPasswordConfigurator.set_apm_system_password(self, new_password, stdout=False)
```

Reset the builtin apm_system user

- *param:* new_password: The new password
- *param:* stdout: Print status to stdout
- *return* True, if successfully reset

### set_beats_password
```python
ElasticPasswordConfigurator.set_beats_password(self, new_password, stdout=False)
```

Reset the builtin beats user

- *param:* new_password: The new password
- *param:* stdout: Print status to stdout
- *return* True, if successfully reset

### set_elastic_password
```python
ElasticPasswordConfigurator.set_elastic_password(self, new_password, stdout=False)
```

Reset the builtin elastic user

- *param:* new_password: The new password
- *param:* stdout: Print status to stdout
- *return* True, if successfully reset

### set_kibana_password
```python
ElasticPasswordConfigurator.set_kibana_password(self, new_password, stdout=False)
```

Reset the builtin kibana user

- *param:* new_password: The new password
- *param:* stdout: Print status to stdout
- *return* True, if successfully reset

### set_logstash_system_password
```python
ElasticPasswordConfigurator.set_logstash_system_password(self, new_password, stdout=False)
```

Reset the builtin logstash user

- *param:* new_password: The new password
- *param:* stdout: Print status to stdout
- *return* True, if successfully reset

### set_remote_monitoring_password
```python
ElasticPasswordConfigurator.set_remote_monitoring_password(self, new_password, stdout=False)
```

Reset the builtin remote_monitoring_user user

- *param:* new_password: The new password
- *param:* stdout: Print status to stdout
- *return* True, if successfully reset

### set_all_passwords
```python
ElasticPasswordConfigurator.set_all_passwords(self, new_password, stdout=False)
```

Reset all builtin user passwords

- *param:* new_password: The new password
- *param:* stdout: Print status to stdout
- *return* True, if successfully reset

## ElasticInstaller
```python
ElasticInstaller(self, host='0.0.0.0', port=9200, password='changeme', configuration_directory='/etc/dynamite/elasticsearch/', install_directory='/opt/dynamite/elasticsearch/', log_directory='/var/log/dynamite/elasticsearch/')
```

Provides a simple interface for installing a new ElasticSearch node

### download_elasticsearch
```python
ElasticInstaller.download_elasticsearch(stdout=False)
```

Download ElasticSearch archive

- *param:* stdout: Print output to console

### extract_elasticsearch
```python
ElasticInstaller.extract_elasticsearch(stdout=False)
```

Extract ElasticSearch to local install_cache

- *param:* stdout: Print output to console

### setup_elasticsearch
```python
ElasticInstaller.setup_elasticsearch(self, stdout=False)
```

Create required directories, files, and variables to run ElasticSearch successfully;
Setup Java environment

- *param:* stdout: Print output to console

## ElasticProfiler
```python
ElasticProfiler(self, stderr=False)
```

Interface for determining whether ElasticSearch is installed/configured/running properly.

## ElasticProcess
```python
ElasticProcess(self)
```

An interface for start|stop|status|restart of the ElasticSearch process

### start
```python
ElasticProcess.start(self, stdout=False)
```

Start the ElasticSearch process
- *param:* stdout: Print output to console
- *return* True, if started successfully

### stop
```python
ElasticProcess.stop(self, stdout=False)
```

Stop the ElasticSearch process

- *param:* stdout: Print output to console
- *return* True if stopped successfully

### restart
```python
ElasticProcess.restart(self, stdout=False)
```

Restart the ElasticSearch process

- *param:* stdout: Print output to console
- *return* True if started successfully

### status
```python
ElasticProcess.status(self)
```

Check the status of the ElasticSearch process

- *return* A dictionary containing the run status and relevant configuration options

## install_elasticsearch
```python
install_elasticsearch(password='changeme', install_jdk=True, create_dynamite_user=True, stdout=False)
```

Install ElasticSearch

- *param:* password: The password used for authentication across all builtin users
- *param:* install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
- *param:* create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run Logstash/ElasticSearch
- *param:* stdout: Print the output to console
- *return* True, if installation succeeded

## uninstall_elasticsearch
```python
uninstall_elasticsearch(stdout=False, prompt_user=True)
```

Uninstall ElasticSearch

- *param:* stdout: Print the output to console
- *param:* prompt_user: Print a warning before continuing
- *return* True, if uninstall succeeded

