```bash
usage: kibana package [-h] [--stdout] [--verbose] [--package-install-path PACKAGE_INSTALL_PATH] [--username USERNAME] [--password PASSWORD] [--saved-object-type SAVED_OBJECT_TYPE] {install,list,list-saved-objects,uninstall}

positional arguments:
  {install,list,list-saved-objects,uninstall}

optional arguments:
  -h, --help            show this help message and exit
  --stdout              Print output to console
  --verbose             Include detailed debug messages
  --package-install-path PACKAGE_INSTALL_PATH
                        The path to the package to install
  --username USERNAME   The name of the Kibana user to authenticate with
  --password PASSWORD   The corresponding Kibana password
  --saved-object-type SAVED_OBJECT_TYPE
                        One of the following supported saved_object types: ['config', 'dashboard', 'index-pattern', 'search', 'timelion-sheet', 'visualization']


```