## Inspection Interface(s)

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