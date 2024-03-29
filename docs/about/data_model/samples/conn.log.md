---
title: conn.log
---
## Zeek `conn.log`

General information regarding TCP, UDP, and ICMP traffic.

### Likely DNS Multicast Traffic

```json
{
	"@timestamp": "2021-01-15T03:09:58.604Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"ephemeral_id": "401fd4f5-0c05-4bbe-967c-89e7ba50a218",
		"type": "filebeat",
		"version": "7.9.2"
	},
	"destination": {
		"address": "224.0.0.251",
		"port": 5353,
		"bytes": 0,
		"ip": "224.0.0.251",
		"packets": 0,
		"mac": "01:00:5e:00:00:fb"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"kind": "event",
		"created": "2021-01-15T03:10:11.676987153Z",
		"module": "zeek",
		"id": "Cheuyi0axMSZadhHg",
		"category": [
			"network",
			"network"
		],
		"type": [
			"connection",
			"start"
		],
		"dataset": "zeek.connection"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"fileset": {
		"name": "connection"
	},
	"host": {
		"name": "sensor-dev"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/conn.log"
		},
		"offset": 474
	},
	"network": {
		"protocol": "dns",
		"community_id": "1:L7sPAjk4l04Uq1b+1PF2pGezp/c=",
		"bytes": 73,
		"transport": "udp",
		"packets": 1,
		"direction": "outbound"
	},
	"related": {
		"ip": [
			"172.16.23.1",
			"224.0.0.251"
		]
	},
	"service": {
		"type": "zeek"
	},
	"source": {
		"address": "172.16.23.1",
		"port": 5353,
		"bytes": 73,
		"ip": "172.16.23.1",
		"packets": 1,
		"mac": "00:50:56:c0:00:01"
	},
	"tags": [
		"zeek.connection",
		"local_orig"
	],
	"zeek": {
		"session_id": "Cheuyi0axMSZadhHg",
		"connection": {
			"local_resp": false,
			"community_id": "1:L7sPAjk4l04Uq1b+1PF2pGezp/c=",
			"orientation": "multicast",
			"local_orig": true,
			"missed_bytes": 0,
			"history": "D",
			"state": "S0",
			"state_message": "Connection attempt seen, no reply.",
			"pcr": 1
		}
	}
}
```