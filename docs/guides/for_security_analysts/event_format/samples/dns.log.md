---
title: dns.log
---
## Zeek `dns.log`

DNS queries along with their responses.

### PTR Record Lookup on Local Network

```json
{
	"@timestamp": "2021-01-12T19:59:52.595Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"type": "filebeat",
		"ephemeral_id": "437ed064-9295-43af-9e84-e5bb38665cd8",
		"version": "7.9.2"
	},
	"destination": {
		"address": "224.0.0.251",
		"port": 5353,
		"ip": "224.0.0.251"
	},
	"dns": {
		"question": {
			"registered_domain": "_tcp.local",
			"top_level_domain": "local",
			"name": "_spotify-connect._tcp.local",
			"type": "PTR",
			"class": "IN"
		},
		"id": 0,
		"type": "query"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"created": "2021-01-12T20:15:19.225Z",
		"kind": "event",
		"module": "zeek",
		"id": "CqfE721wPELl1yUjt7",
		"type": [
			"connection",
			"info",
			"protocol"
		],
		"category": [
			"network"
		],
		"dataset": "zeek.dns"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"fileset": {
		"name": "dns"
	},
	"host": {
		"name": "sensor-dev"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/dns.log"
		},
		"offset": 0
	},
	"network": {
		"community_id": "1:L7sPAjk4l04Uq1b+1PF2pGezp/c=",
		"transport": "udp"
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
		"ip": "172.16.23.1"
	},
	"tags": [
		"zeek.dns"
	],
	"zeek": {
		"dns": {
			"AA": false,
			"qclass_name": "C_INTERNET",
			"RD": false,
			"community_id": "1:L7sPAjk4l04Uq1b+1PF2pGezp/c=",
			"qtype_name": "PTR",
			"qtype": 12,
			"rejected": false,
			"query": "_spotify-connect._tcp.local",
			"trans_id": 0,
			"qclass": 1,
			"TC": false,
			"RA": false
		},
		"session_id": "CqfE721wPELl1yUjt7"
	}
}
```