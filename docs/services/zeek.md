# dynamite_nsm.services.zeek

## ZeekScriptConfigurator
```python
ZeekScriptConfigurator(self, configuration_directory='/etc/dynamite/zeek/')
```

Wrapper for configuring broctl sites/local.bro

### disable_script
```python
ZeekScriptConfigurator.disable_script(self, name)
```

- *param* name: The name of the script (E.G protocols/http/software)
- *return* True, if the script was successfully disabled

### enable_script
```python
ZeekScriptConfigurator.enable_script(self, name)
```

- *param* name: The name of the script (E.G protocols/http/software)
- *return* True, if the script was successfully enabled

### list_disabled_scripts
```python
ZeekScriptConfigurator.list_disabled_scripts(self)
```

- *return* A list of disabled Zeek scripts

### list_enabled_scripts
```python
ZeekScriptConfigurator.list_enabled_scripts(self)
```

- *return* A list of enabled Zeek scripts

### list_enabled_sigs
```python
ZeekScriptConfigurator.list_enabled_sigs(self)
```

- *return* A list of enabled Zeek signatures

### list_disabled_sigs
```python
ZeekScriptConfigurator.list_disabled_sigs(self)
```

- *return* A list of disabled Zeek signatures

### write_config
```python
ZeekScriptConfigurator.write_config(self)
```

Overwrite the existing local.bro config with changed values

## ZeekNodeConfigurator
```python
ZeekNodeConfigurator(self, install_directory='/opt/dynamite/zeek/')
```

Wrapper for configuring broctl node.cfg

### add_logger
```python
ZeekNodeConfigurator.add_logger(self, name, host)
```

- *param* name: The name of the logger
- *param* host: The host on which the logger is running
- *return* True, if added successfully

### add_manager
```python
ZeekNodeConfigurator.add_manager(self, name, host)
```

- *param* name: The name of the manager
- *param* host: The host on which the manager is running
- *return* True, if added successfully

### add_proxy
```python
ZeekNodeConfigurator.add_proxy(self, name, host)
```

- *param* name: The name of the proxy
- *param* host: The host on which the proxy is running
- *return* True, if added successfully

### add_worker
```python
ZeekNodeConfigurator.add_worker(self, name, interface, host, lb_procs=10, pin_cpus=(0, 1))
```

- *param* name: The name of the worker
- *param* interface: The interface that the worker should be monitoring
- *param* host: The host on which the worker is running
- *param* lb_procs: The number of Zeek processes associated with a given worker
- *param* pin_cpus: Core affinity for the processes (iterable)
- *return* True, if added successfully

### remove_logger
```python
ZeekNodeConfigurator.remove_logger(self, name)
```

- *param* name: The name of the logger
- *return* True, if successfully removed

### remove_manager
```python
ZeekNodeConfigurator.remove_manager(self, name)
```

- *param* name: The name of the manager
- *return* True, if successfully removed

### remove_proxy
```python
ZeekNodeConfigurator.remove_proxy(self, name)
```

- *param* name: The name of the proxy
- *return* True, if successfully removed

### remove_worker
```python
ZeekNodeConfigurator.remove_worker(self, name)
```

- *param* name: The name of the worker
- *return* True, if successfully removed

### list_workers
```python
ZeekNodeConfigurator.list_workers(self)
```

- *return* A list of worker names

### list_proxies
```python
ZeekNodeConfigurator.list_proxies(self)
```

- *return* A list of proxy names

### list_loggers
```python
ZeekNodeConfigurator.list_loggers(self)
```

- *return* A list of logger names

### get_manager
```python
ZeekNodeConfigurator.get_manager(self)
```

- *return* The name of the manager

### write_config
```python
ZeekNodeConfigurator.write_config(self)
```

Overwrite the existing node.cfg with changed values

## ZeekProfiler
```python
ZeekProfiler(self, stderr=False)
```

An interface for profiling Zeek NSM

