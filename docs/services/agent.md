# dynamite_nsm.services.agent

## install_agent
```python
install_agent(network_interface, agent_label, logstash_target)
```

- *param:* network_interface: The network interface that the agent should analyze traffic on
- *param:* agent_label: A descriptive label representing the
segment/location on your network that your agent is monitoring
- *param:* logstash_target: The host port combination for the target Logstash server (E.G "localhost:5044")
- *return* True, if install succeeded

## point_agent
```python
point_agent(host, port)
```

Point the agent to a new logstash host

- *param:* host: The logstash host to forward logs too
- *param:* port: The service port the logstash host is listening on [5044 standard]

## prepare_agent
```python
prepare_agent()
```

Install the necessary build dependencies and kernel-headers

*IMPORTANT A REBOOT IS REQUIRED AFTER RUNNING THIS METHOD*

- *return* True, if successfully prepared

## profile_agent
```python
profile_agent()
```

Get information about installation/running processes within the agent stack

- *return* A dictionary containing the status of each component

## start_agent
```python
start_agent()
```

Start the Zeek (BroCtl) and FileBeats processes

- *return* True, if started successfully

## status_agent
```python
status_agent()
```

Retrieve the status of the agent processes

- *return* A tuple, where the first element is the zeek process status (string), and second element are
         the FileBeats and PF_RING status

## stop_agent
```python
stop_agent()
```

Stop the Zeek (BroCtl) and FileBeats processes

- *return* True, if stopped successfully

## uninstall_agent
```python
uninstall_agent(prompt_user=True)
```

Uninstall the agent

- *param:* prompt_user: Print a warning before continuing
- *return* True, if uninstall succeeded

