# Kibana
DynamiteNSM ships with a simple package manager for managing the installation of
visualizations, dashboards, and saved_searches. These objects are grouped into self-contained packages
that can easily be installed to a specific tenant.


```bash
$ sudo dynamite kibana package -h

usage: dynamite package [-h] {install,list,list-tenants,list-saved-objects,uninstall} ...

positional arguments:
  {install,list,list-tenants,list-saved-objects,uninstall}

optional arguments:
  -h, --help            show this help message and exit
```

## Package Installation
```bash
sudo dynamite kibana package install -h
```

## Package Uninstallation
```bash
sudo dynamite kibana package uninstall -h
```


