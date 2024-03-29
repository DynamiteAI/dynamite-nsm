---
title: weird.log
---

## Zeek `weird.log`
Unexpected network-level activity

### DNS_Conn_count_too_large

```json
{
	"@timestamp": "2021-01-13T17:02:32.864Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"ephemeral_id": "c6462bb8-8609-4620-bd3d-4f8a0cd4f025",
		"type": "filebeat",
		"version": "7.9.2"
	},
	"destination": {
		"address": "224.0.0.251",
		"port": 5353,
		"ip": "224.0.0.251"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"kind": "alert",
		"created": "2021-01-13T17:02:35.501488569Z",
		"module": "zeek",
		"id": "CjSsHj4wXCoOPjhHll",
		"category": [
			"network"
		],
		"type": [
			"info"
		],
		"dataset": "zeek.weird"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"fileset": {
		"name": "weird"
	},
	"host": {
		"name": "sensor-dev"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/weird.log"
		},
		"offset": 0
	},
	"related": {
		"ip": [
			"172.16.23.1",
			"224.0.0.251"
		]
	},
	"rule": {
		"name": "DNS_Conn_count_too_large"
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
		"zeek.weird"
	],
	"zeek": {
		"weird": {
			"peer": "dynamite-worker-ens37-7",
			"name": "DNS_Conn_count_too_large",
			"notice": false
		},
		"session_id": "CjSsHj4wXCoOPjhHll"
	}
}
```