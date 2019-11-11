# dynamite_nsm.services.monitor

## install_monitor
```python
install_monitor(elasticsearch_password='changeme')
```

Installs Logstash (with ElastiFlow templates modified to work with Zeek), ElasticSearch, and Kibana.

:return: True, if installation succeeded

## profile_monitor
```python
profile_monitor()
```

Get information about installation/running processes within the monitor stack

:return: A dictionary containing the status of each component

## start_monitor
```python
start_monitor()
```

Starts ElasticSearch, Logstash, and Kibana on localhost

:return: True, if successfully started

## status_monitor
```python
status_monitor()
```

Retrieve the status of the monitor processes

:return: A tuple where the first element is elasticsearch status (dict), second is logstash status (dict),
and third is Kibana status.

## stop_monitor
```python
stop_monitor()
```

Stops ElasticSearch, Logstash, and Kibana on localhost

:return: True, if successfully stopped

## uninstall_monitor
```python
uninstall_monitor(prompt_user=True)
```

Uninstall standalone monitor components (ElasticSearch, Logstash, and Kibana)

:return: True, if uninstall successful

