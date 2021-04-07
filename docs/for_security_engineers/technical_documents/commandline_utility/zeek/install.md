```bash
root@jamin-dev:~# dynamite zeek install -h
usage: dynamite install [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--install-directory INSTALL_DIRECTORY] [--download-zeek-archive] [--stdout] [--verbose]
                        [--capture-network-interfaces CAPTURE_NETWORK_INTERFACES [CAPTURE_NETWORK_INTERFACES ...]]

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        Path to the configuration directory (E.G /etc/dynamite/zeek/)
  --install-directory INSTALL_DIRECTORY
                        Path to the install directory (E.G /opt/dynamite/zeek/)
  --download-zeek-archive
                        If True, download the Zeek archive from a mirror
  --stdout              Print output to console
  --verbose             Include detailed debug messages
  --capture-network-interfaces CAPTURE_NETWORK_INTERFACES [CAPTURE_NETWORK_INTERFACES ...]
                        A list of network interfaces to capture on (E.G ["mon0", "mon1"])
```