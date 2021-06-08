# Configure Management Interface

The management interface is used for connecting to a variety of services available for viewing and working with data 
produced by the agent.

You can use DHCP for the management interface, however within production environments static network interfaces are 
encouraged.

### `/etc/network/interfaces`

#### DHCP

```
auto eth0
iface eth0 inet dhcp
```

#### Static

```
auto eth0
iface eth0 inet static
  address 192.168.1.14
  gateway 192.168.1.1
  netmask 255.255.255.0
  network 192.168.1.0
  broadcast 192.168.1.255
  dns-nameservers 192.168.1.1 192.168.1.2
```

## Post Configuration
Once your interfaces are setup. Reboot to apply the changes.

Once the reboot is complete, confirm that your interface is up with a tool such as `ifconfig`.
