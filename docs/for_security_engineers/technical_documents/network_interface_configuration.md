# Network Interface Configuration

## Management Interface

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


## Monitoring Interface(s)

Monitoring interfaces receive traffic from a SPAN port or TAP device. Typically, they do not need IP addresses.

Additionally, any NIC offloading functions such as `tso`, `gso`, and `gro` should be disabled.

### `/etc/network/interfaces`
```
auto mon0
iface mon0 inet manual
  up ifconfig $IFACE -arp up
  up ip link set $IFACE promisc on
  down ip link set $IFACE promisc off
  down ifconfig $IFACE down
  post-up for i in rx tx sg tso ufo gso gro lro; do ethtool -K $IFACE $i off; done
  post-up echo 1 > /proc/sys/net/ipv6/conf/$IFACE/disable_ipv6
```

## Post Configuration
Once your interfaces are setup. Reboot to apply the changes.

Once the reboot is complete, confirm that both your management and monitoring interfaces are available and up with a 
tool such as `ifconfig`.
