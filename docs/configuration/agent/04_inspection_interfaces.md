# Inspection Interfaces

> ⚠️ Changes made within these interfaces require that Zeek and/or Suricata be restarted. Typically, the easiest way to 
> accomplish this is via the command:
> `sudo dynamite agent process restart`

With so many networks now being defined in software adding and removing inspection interfaces in production, settings 
is becoming much more commonplace.

At this time, the `dynamite` commandline utility does not provide the ability to directly modify this section of the 
relevant configurations. 

Users can however use the `agent optimize` command to re-balance resources against any added/deleted inspection interfaces.

```bash
dynamite agent optimize --inspect-interfaces ens33 ens34 ens36 --verbose
2021-06-10 12:33:12 AGENT.THREAD_OPTIMIZE     INFO       | 8 CPU cores detected.
2021-06-10 12:33:12 AGENT.THREAD_OPTIMIZE     INFO       | Both Zeek and Suricata are installed. Allocating 60% of resources to Zeek, 30% to Suricata, and 10% to Kernel.
```

## Configuration Files

### Zeek

By default DynamiteNSM will install Zeek's `node.cfg` at `/opt/dynamite/zeek/etc/node.cfg`.

```ini
[dynamite-logger]
type = logger
host = localhost

[dynamite-proxy-1]
type = proxy
host = localhost

[dynamite-worker-ens33]
type = worker
interface = af_packet::ens33
lb_method = custom
af_packet_fanout_id = 30983
af_packet_fanout_mode = AF_Packet::FANOUT_HASH
lb_procs = 5
pin_cpus = 1,2,3,4,5
host = localhost

[dynamite-manager]
type = manager
host = localhost
```

### Suricata
By default, Suricata's main config will be installed to `/etc/dynamite/suricata/suricata.yaml`
Suricata provides a `threading` section for pinning CPUs to `thread-families`.
```yaml
threading:
  cpu-affinity:
  - management-cpu-set:
      cpu:
      - 6
  - receive-cpu-set:
      cpu:
      - 7
  - worker-cpu-set:
      cpu:
      - 7
      mode: exclusive
      threads: 1
  set-cpu-affinity: true
```