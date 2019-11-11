# dynamite_nsm.services.suricata

## SuricataConfigurator
```python
SuricataConfigurator(self, configuration_directory='/etc/dynamite/suricata/')
```

Wrapper for configuring suricata.yml


### add_pfring_interface
```python
SuricataConfigurator.add_pfring_interface(self, interface, threads=None, cluster_id=None, bpf_filter=None)
```

Add a new PF_RING interface to monitor

- *param* interface: The name of the interface to monitor (eth0, mon0)
- *param* threads: "auto" or the number of threads
- *param* cluster_id: The PF_RING cluster id; PF_RING will load balance packets based on flow
- *param* bpf_filter: bpf filter for this interface (E.G tcp)
- *return:* None

### remove_pfring_interface
```python
SuricataConfigurator.remove_pfring_interface(self, interface)
```

Remove an existing PF_RING interface

- *param* interface: The name of the interface to remove (eth0, mon0)
- *return:* None

### write_config
```python
SuricataConfigurator.write_config(self)
```

Overwrite the existing suricata.yaml config with changed values

## SuricataProfiler
```python
SuricataProfiler(self, stderr=False)
```

An interface for profiling Suricata IDS

## SuricataProcess
```python
SuricataProcess(self)
```

An interface for start|stop|status|restart of the Suricata process

### start
```python
SuricataProcess.start(self, stdout=False)
```

Start Suricata IDS process in daemon mode

- *param* stdout: Print output to console
- *return:* True, if started successfully

### stop
```python
SuricataProcess.stop(self, stdout=False)
```

Stop the Suricata process

- *param* stdout: Print output to console
- *return:* True if stopped successfully

### restart
```python
SuricataProcess.restart(self, stdout=False)
```

Restart the Suricata process

- *param* stdout: Print output to console
- *return:* True if restarted successfully

### status
```python
SuricataProcess.status(self)
```

Check the status of the Suricata process

- *return:* A dictionary containing the run status and relevant configuration options

