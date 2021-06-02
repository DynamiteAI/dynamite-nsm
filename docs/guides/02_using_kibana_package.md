# Working with Kibana Package Manager

[Kibana package manager](/services/04_kibana_package) can be used to install custom visualization packages useful for viewing your network
from many perspectives.

### There are 5 sub-commands for the package manager.
* **Install** - Installs one or many packages from the provided path.
* **Uninstall** - Uninstall packages interactively or by providing a package id.
* **List** - List installed packages and their related saved objects.
* **List Saved Objects** - List all saved objects irrespective of their relationship to packages.
* **List Tenants** - List tenants available to be used as installation destinations if multitenancy is enabled.

### Install a package
Installation of a package is straightforward, supply the path to the package to be installed and the credentials required for authenticating to Kibana.
```bash
~$ sudo dynamite kibana package install --path packages/investigator.tar.xz --username <username> --password <password>
```

>
KIBANA.PACKAGE    INFO    | Checking connection to Kibana.  
KIBANA.PACKAGE    INFO    | Installing from TAR archive: packages/investigator.tar.xz.  
KIBANA.PACKAGE    INFO    | Dynamite Investigator installation succeeded!  
OK

### Uninstall a package
By default packages are uninstalled interactively unless the `--package-id` parameter is passed.  
The number of options in the interactive uninstallation flow can be narrowed down by using the `--package-name` option, and only packages matching that string will be returned to the uninstaller.

``` bash
~$ sudo dynamite kibana package uninstall --username <username> --password <password>
```
>
Select a package to uninstall:  

>[1] Protocol Piechart - [private]  
       * Basic piechart displaying traffic by protocol  

>[2] Dynamite Investigator - [global]  
       * Provides basic tools for investigation  

>Select package(s) to uninstall (For example: "1 2 3 5 8")

### List installed packages
Get meta information about the installed packages and details about the objects contained within them.
By default listing installed packages returns data in JSON format, use the `--pretty` option to get a human readable table.
``` bash
~$ sudo dynamite kibana package list --username <username> --password <password>
```

### List installed saved objects
Returns information regarding the saved objects installed on the kibana instance whether or not they are part of a package.
By default listing installed saved returns data in JSON format, use the `--pretty` option to get a human readable table.
``` bash
~$ sudo dynamite kibana package list-saved-objects --username <username> --password <password>
```

### List Tenants
Lists the available OpenSearch Tenants that can be used as installation destinations, by default packages are installed to the `global` tenant.
By default listing tenants returns data in JSON format, use the `--pretty` option to get a human readable table.
``` bash
~$ sudo dynamite kibana package list-tenants --username <username> --password <password>
```