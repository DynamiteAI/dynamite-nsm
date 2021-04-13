---
title: SPAN vs TAP
---

## Introduction

To be able to start forwarding events an agent must be deployed on a SPAN port or a network TAP. Both have their advantages and disadvantages.

- A **SPAN port** (Switch Port Analyzer), is a feature provided by most managed switches, essentially a device is plugged into this span port.

- A **network TAP** (Test Access Point) a dedicated device that transmit both the send and receive data streams simultaneously on separate channels. They are deployed in-line and are a single point of failure. Be careful when choosing a network tap!


## Pros and Cons

### Span Ports

<center>
    <img src="/data/img/span_diagram.png">
</center>

- Available on almost all managed switches
- Does not sit inline, if the span port fails, it will not disrupt network connectivity.
- Remotely configurable

### Network Taps

<center>
    <img src="/data/img/tap_diagram.png">
</center>

- A high quality tap typically handles much better under high traffic load (will not drop packets.)
- Court admissible and provides forensically sound data/evidence.
- Have no IP address and no MAC address and are not vulnerable to conventional network attacks.

## Conclusion

At the end of the day, network TAPs usually emerge as the best option, but SPAN ports are a very reasonable alternative if you expect low-medium levels of traffic or do not care especially about dropped packets.