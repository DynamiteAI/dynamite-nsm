---
title: dhcp.log
---
## Zeek `dhcp.log`
DHCP “conversation” defined by messages exchanged within a relatively short period of time using the same transaction ID

### DHCP `REQUEST` and `ACK`

```json
{
	"@timestamp": "2021-01-12T20:08:18.367Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"type": "filebeat",
		"ephemeral_id": "437ed064-9295-43af-9e84-e5bb38665cd8",
		"version": "7.9.2"
	},
	"client": {
		"address": "172.16.23.128"
	},
	"destination": {
		"address": "172.16.23.254",
		"port": 67,
		"ip": "172.16.23.254"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"kind": "event",
		"created": "2021-01-12T20:15:26.551936060Z",
		"module": "zeek",
		"id": "{0=CcO3R42oSYdJMEIeS5}",
		"category": [
			"network"
		],
		"type": [
			"connection",
			"protocol",
			"info"
		],
		"dataset": "zeek.dhcp"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"fileset": {
		"name": "dhcp"
	},
	"host": {
		"name": "sensor-dev"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/dhcp.log"
		},
		"offset": 0
	},
	"network": {
		"community_id": "1:fwVMujs9487i/LsEdet5jezcpFc=",
		"protocol": "dhcp",
		"name": "localdomain",
		"transport": "udp"
	},
	"related": {
		"ip": [
			"172.16.23.128",
			"172.16.23.254"
		]
	},
	"server": {
		"address": "172.16.23.254"
	},
	"service": {
		"type": "zeek"
	},
	"source": {
		"address": "172.16.23.128",
		"port": 68,
		"ip": "172.16.23.128"
	},
	"tags": [
		"zeek.dhcp"
	],
	"zeek": {
		"session_id": [
			"CcO3R42oSYdJMEIeS5"
		],
		"dhcp": {
			"msg": {
				"types": [
					"REQUEST",
					"ACK"
				],
				"origin": [
					"172.16.23.128",
					"172.16.23.254"
				]
			},
			"duration": 0,
			"hostname": "sensor-dev",
			"address": {
				"server": "172.16.23.254",
				"client": "172.16.23.128",
				"assigned": "172.16.23.128",
				"mac": "00:0c:29:c6:7e:2c"
			},
			"lease_time": 1800,
			"domain": "localdomain"
		}
	}
}
```