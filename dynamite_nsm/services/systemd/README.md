## Overview

The systemd package adds the parts needed to use Linux systemd to manage Dynamite services.  Systemd allow us to leverage Linux native mechanisms for process and thread management, customizing runtime environments and interacting with any of the loaded services via an efficient command line interface.  There are few pieces:

* `dynamite.target` : Systemd target (e.g. runlevel) that defines the services that should be grouped together and treated as one.
* `<name>.service`  : Service-specific unit files, that point back to the target. Also define command line strings used to start/stop/restart services. 
* `systemd.py`      : Defines the dynctl() Python class. This class provides an interface for (un)installing and managing the parts needed to use systemd for all Dynamite process management.  

Our use of systemd is fairly simple.  Each Dynamite component has its own systemd unit file.  The _dynamite.target_ unit points to each service unit, binding them a single component referred to as a _target_ that can be started and stopped like any other service.  

_dynamite.target_ is the only unit file that gets enabled at install-time.  The two-way relationship between the target and each service ensures everything operates as one, which hugely simplifies things on the management end.  As a bonus, each service can also be managed directly, customize what is running and what isn't, in real time, without meddling with underlying config files.  

The Python class dynctl() provides the mechanisms for interacting with systemd using the native `systemctl` command line interface.  This means, we shell-out to `systemctl` whenever we need to interact with a service.  This isn't great, but far better than trying to build a custom systemctl-like interface for communicating with systemd over dbus.  

## Design Principles 

Instance oriented - The state of dynamite agent component is maintained within instance variables in the form `dynctl().<component name>_running` and `dynctl().<component name>_enabled` to reflect the current state to keep from extra calls to _status_ methods 

No environment vars passed on cli - Instead use each tool's native config file to provide engine-level customizations.  Inspection interfaces, for example are already being defined by the installer at config time.  

## Usage 

The dynctl() class is meant to be used as a class instance, e.g. `dc = dynctl()`.  The tricky thing about using the systemctl utility is that it will sometimes return a `0` exit code, even if the underlying operation failed.  With that, the general idea is that anytime you interact with the class, the state attributes for the installed components get updated in the dynctl() class instance.  That is, we try to keep track of service/target state dynamically, so we don't have to make a bunch of extra calls to systemctl to find out the outcome of an operation.  

*Install*

Instantiate a class instance. Do this before calling any methods.  
```python
dc = dynctl()
```

Then call the the _install_agent_unit_files()_ method
```python
dc.install_agent_unit_files()
```

This will install the unit files and enable the *dynamite.target*. All agent services will then be set to start at boot after network services have initialized.  

*Uninstall*

Same as above.  This reverses the operations performed during installation.  
```python
dc.uninstall_agent_unit_files()
```

*Start the Agent*

The equivalent of running `dynamite start agent` only using systemd for process management.  
```python
dc.start_agent()
```

*Stop the Agent*

The equivalent of running `dynamite stop agent` only using systemd for process management.  
```python
dc.stop_agent()
```

*Stop a specific service*

The equivalent of running `dynamite stop <component>` where component is the service name.  There are convenience methods for each Dynamite agent component.  For example, to stop zeek:
```python
dc.stop_zeek()
```

*Enable/disable a specific service*

We now have the ability to easily enable and disable specific components after the agent has been installed.  For example, to disable zeek:

```python
dc.disable('zeek')
```
Or to temporarily disable all agent services, use the dynctl() convenience method:
```python
dc.disable_agent()
```
Or to do this live on the Linux command line, just use systemctl:
```bash
sudo systemctl disable zeek.service
```
```bash
sudo systemctl enable zeek.service
```

