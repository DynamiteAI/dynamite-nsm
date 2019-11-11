# dynamite_nsm.services.logstash

## LogstashConfigurator
```python
LogstashConfigurator(self, configuration_directory)
```

Wrapper for configuring logstash.yml and jvm.options

### get_elasticsearch_password
```python
LogstashConfigurator.get_elasticsearch_password()
```

- *return* The password for the given ElasticSearch instance

### get_log_path
```python
LogstashConfigurator.get_log_path(self)
```

- *return* The path to Logstash logs on filesystem

### get_node_name
```python
LogstashConfigurator.get_node_name(self)
```

- *return* The name of the LogStash collector node

### get_data_path
```python
LogstashConfigurator.get_data_path(self)
```

- *return* The directory where data (persistent queues) are being stored

### get_pipeline_batch_size
```python
LogstashConfigurator.get_pipeline_batch_size(self)
```

- *return* The number of events to retrieve from inputs before sending to filters+workers

### get_pipeline_batch_delay
```python
LogstashConfigurator.get_pipeline_batch_delay(self)
```

- *return* The number of milliseconds while polling for the next event before dispatching an
undersized batch to filters+outputs

### get_jvm_initial_memory
```python
LogstashConfigurator.get_jvm_initial_memory(self)
```

- *return* The initial amount of memory the JVM heap allocates

### get_jvm_maximum_memory
```python
LogstashConfigurator.get_jvm_maximum_memory(self)
```

- *return* The maximum amount of memory the JVM heap allocates

### set_elasticsearch_password
```python
LogstashConfigurator.set_elasticsearch_password(password)
```

- *param* password: The new password

### set_log_path
```python
LogstashConfigurator.set_log_path(self, path)
```

- *param* path: The path to Logstash logs on the filesystem

### set_node_name
```python
LogstashConfigurator.set_node_name(self, name)
```

- *param* name: The name of the Logstash collector node

### set_data_path
```python
LogstashConfigurator.set_data_path(self, path)
```

- *param* path: The path to the Logstash collector node

### set_pipeline_batch_size
```python
LogstashConfigurator.set_pipeline_batch_size(self, event_count)
```

- *param* event_count: How many events to retrieve from inputs before sending to filters+workers

### set_pipeline_batch_delay
```python
LogstashConfigurator.set_pipeline_batch_delay(self, delay_millisecs)
```

- *param* delay_millisecs: How long to wait in milliseconds while polling for the next event before dispatching an
undersized batch to filters+outputs

### set_jvm_initial_memory
```python
LogstashConfigurator.set_jvm_initial_memory(self, gigs)
```

- *param* gigs: The amount of initial memory (In Gigabytes) for the JVM to allocate to the heap

### set_jvm_maximum_memory
```python
LogstashConfigurator.set_jvm_maximum_memory(self, gigs)
```

- *param* gigs: The amount of maximum memory (In Gigabytes) for the JVM to allocate to the heap

### write_configs
```python
LogstashConfigurator.write_configs(self)
```

Write (and backs-up) logstash.yml and jvm.option configurations

## LogstashInstaller
```python
LogstashInstaller(self, host='0.0.0.0', elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme', configuration_directory='/etc/dynamite/logstash/', install_directory='/opt/dynamite/logstash/', log_directory='/var/log/dynamite/logstash/')
```

Provides a simple interface for installing a new Logstash collector with ElastiFlow pipelines

### download_logstash
```python
LogstashInstaller.download_logstash(stdout=False)
```

Download Logstash archive

- *param* stdout: Print output to console

### extract_logstash
```python
LogstashInstaller.extract_logstash(stdout=False)
```

Extract Logstash to local install_cache

- *param* stdout: Print output to console

### setup_logstash
```python
LogstashInstaller.setup_logstash(self, stdout=False)
```

Create required directories, files, and variables to run LogStash successfully;

- *param* stdout: Print output to console

## LogstashProfiler
```python
LogstashProfiler(self, stderr=False)
```

Interface for determining whether Logstash is installed/configured/running properly.

## LogstashProcess
```python
LogstashProcess(self)
```

An interface for start|stop|status|restart of the LogStash process

### start
```python
LogstashProcess.start(self, stdout=False)
```

Start the LogStash process
- *param* stdout: Print output to console
- *return* True if started successfully

### stop
```python
LogstashProcess.stop(self, stdout=False)
```

Stop the LogStash process

- *param* stdout: Print output to console
- *return* True if stopped successfully

### restart
```python
LogstashProcess.restart(self, stdout=False)
```

Restart the LogStash process

- *param* stdout: Print output to console
- *return* True if started successfully

### status
```python
LogstashProcess.status(self)
```

Check the status of the LogStash process

- *return* A dictionary containing the run status and relevant configuration options

## install_logstash
```python
install_logstash(host='0.0.0.0', elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme', install_jdk=True, create_dynamite_user=True, stdout=False)
```

Install Logstash/ElastiFlow
- *param* host: The IP address to bind LogStash listeners too
- *param* elasticsearch_password: The password used for authentication across all builtin ES users
- *param* elasticsearch_host: A hostname/IP of the target elasticsearch instance
- *param* elasticsearch_port: A port number for the target elasticsearch instance
- *param* elasticsearch_password: The password used for authentication across all builtin ES users
- *param* install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
- *param* create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run Logstash/ElasticSearch
- *param* stdout: Print the output to console
- *return* True, if installation succeeded

## uninstall_logstash
```python
uninstall_logstash(stdout=False, prompt_user=True)
```

Uninstall Logstash/ElastiFlow

- *param* stdout: Print the output to console
- *param* prompt_user: Print a warning before continuing
- *return* True, if uninstall succeeded

