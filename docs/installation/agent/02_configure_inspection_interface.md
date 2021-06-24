## Inspection Interface(s)

Inspection interfaces receive traffic from a [SPAN port or TAP device](../../../requirements/04_span_vs_tap). Typically, they do not need IP addresses.

> ⓘ A notable exception is on AWS's [port-mirroring implementation for VPCs](https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html) which relies on VXLAN 
> encapsulation requiring the monitored interface to have a routable ip address.

Disabling any NIC offloading functions such as `tso`, `gso`, and `gro` can also improve performance.

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