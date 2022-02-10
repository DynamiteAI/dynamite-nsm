# Setup
Before any Dynamite services can be installed and managed the setup bootstrapper must be called. Setup provides two modes
`install` and `uninstall`. 

The `install` command retrieves the latest default configurations, sets up the directory structure, and creates a 
`dynamite` policy in the `/etc/sudoers.d/` directory. 

```bash
$ sudo dynamite setup -h
usage: dynamite [-h] {install,uninstall} ...

Setup DynamiteNSM 1.1.2

positional arguments:
  {install,uninstall}
    install            Setup required files and directories.
    uninstall          Uninstall DynamiteNSM on this machine.

optional arguments:
  -h, --help           show this help message and exit
```

