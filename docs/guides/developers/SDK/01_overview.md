# SDK Overview


## Highlevel Design Concepts

DynamiteNSM provides several entry points for developers to build their own utilities or automate a deployment process.

The DynamiteNSM SDK is divided into two major sub-modules: `services` and `cmd`.

- The `services` module provides a common set of wrappers around various utilities.
- The `cmd` module provides a set of functions and classes for converting `services` into fully functioning commandline utilities. 

### Services Module (`services`)
The `services` module is essentially a collection of submodules for managing the `installation`, `configuration`, `process management`, 
and `monitoring` of utilities currently supported within our stack. 
All services inherit from interfaces found within the `service.base` submodule.

One of our driving design principles for this module was to use similar patterns of abstraction across all supported services.

For example, the underlying mechanics of enabling a Suricata Rule-set verses a Zeek script are essentially identical, allowing us to present very
similar configuration managers for each.

```text
[+] ├─ dynamite_nsm/ 
[-]  ├─ cmd/
[+]  ├─ services/
[+]     ├─ zeek/
         ├─ install.py
         ├─ logs.py
         ├─ uninstall.py
         ├─ config.py
         ├─ process.py
         ├─ profile.py
[-]     ├─ suricata/
[-]     ├─ filebeat/
[-]     ├─ elasticsearch/
[-]     ├─ logstash/
[-]     ├─ kibana/
[-]     ├─ base/
     ├─ const.py
     ├─ exceptions.py
     ├─ logger.py
     ├─ package_manager.py
     ├─ utilities.py
```

| Submodule Module | Description                                                                                                         | Corresponding Base Classes                 |
|---------------|---------------------------------------------------------------------------------------------------------------------|--------------------------------------------|
| install       | An interface to manage the installation of a service.                                                               | `BaseInstallManager`                       |
| uninstall     | An interface to manage the uninstallation of a service.                                                             | `BaseUninstallManager`                     |
| config        | An interface for interacting with various configurations available to the service.                                  | `GenericConfigManager` `YamlConfigManager` |
| logs          | An interface for searching through various logs.                                                                    | `LogFile`                                  |
| process       | An interface for managing process state (`start` `stop` `status` `restart`)                                         | `BaseProcessManager`                       |
| profile       | An interface the provides a set of checks against a service to ensure that it is installed and configured properly. | `BaseProcessProfiler`                      |

### Commandline Builder Module (`cmd`)

The `cmd` module comes with a set of functions for converting  `service.config`, `service.install`, `service.process`, and `service.logs` classes into
commandline utilities that are invokable under the `/usr/local/bin/dynamite` utility. 

> ⓘ If you are interested in building your own service and commandline utility check out this [guide](/guides/developers/02_build_a_commandline_utility).


```text
[+] ├─ dynamite_nsm/ 
[+]  ├─ cmd/
[-]     ├─ zeek/
[-]        ├─ config/
[+]        ├─ install/
              ├─ __main__.py
              ├─ __init__.py
[-]        ├─ logs/
[-]        ├─ process/
[-]        ├─ uninstall/
[-]     ├─ suricata/
[-]     ├─ filebeat/
[-]     ├─ elasticsearch/
[-]     ├─ kibana/
[-]     ├─ logstash/
[-]     ├─ updates/
        ├─ base_interface.py
        ├─ config_object_interfaces.py
        ├─ service_interfaces.py
        ├─ inspection_helpers.py
        ├─ interface_operations.py
```


| CMD SDK Module           | Description                                                                                   |
|--------------------------|-----------------------------------------------------------------------------------------------|
| base_interface           | Abstract base interface implemented by all interface modules                                  |
| service_interfaces       | Provides commandline wrappers for many `service.base` action classes.                         |
| config_object_interfaces | Provides commandline wrappers for complex config objects.                                     |
| inspection_helpers       | Provides a set of utility functions and classes for building commandline parsers dynamically. |
| interface_operations     | Provides a set of utility functions for combining commandline interfaces.                     |
