---
title: ssh.log
---

## Zeek `ssh.log`

SSH connections with authentication attempts

### Successful SSH Authentication

```json
{
	"@timestamp": "2021-01-18T20:25:14.252Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"type": "filebeat",
		"ephemeral_id": "9b5aa2d4-1b54-4c25-bd2d-61cd592d34f4",
		"version": "7.9.2"
	},
	"destination": {
		"address": "192.168.194.128",
		"port": 22,
		"ip": "192.168.194.128"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"kind": "event",
		"created": "2021-01-18T20:25:23.314784943Z",
		"module": "zeek",
		"id": "CTmQup3tXKmgr92ECk",
		"category": [
			"network"
		],
		"type": [
			"connection",
			"protocol"
		],
		"dataset": "zeek.ssh",
		"outcome": "success"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"fileset": {
		"name": "ssh"
	},
	"host": {
		"name": "sensor-dev"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/ssh.log"
		},
		"offset": 0
	},
	"network": {
		"protocol": "ssh",
		"community_id": "1:9u7Q4Aw1yFu7z67axSzldRRGJJ4=",
		"transport": "tcp"
	},
	"related": {
		"ip": [
			"192.168.194.1",
			"192.168.194.128"
		]
	},
	"service": {
		"type": "zeek"
	},
	"source": {
		"address": "192.168.194.1",
		"port": 49760,
		"ip": "192.168.194.1"
	},
	"tags": [
		"zeek.ssh"
	],
	"zeek": {
		"ssh": {
			"server": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1",
			"host_key": "24:c3:65:22:da:ed:29:48:80:ae:df:de:74:25:cb:b6",
			"community_id": "1:9u7Q4Aw1yFu7z67axSzldRRGJJ4=",
			"auth": {
				"success": true,
				"attempts": 1
			},
			"client": "SSH-2.0-OpenSSH_8.1",
			"version": 2,
			"algorithm": {
				"cipher": "chacha20-poly1305@openssh.com",
				"host_key": "ecdsa-sha2-nistp256",
				"compression": "none",
				"key_exchange": "curve25519-sha256",
				"mac": "umac-64-etm@openssh.com"
			}
		},
		"session_id": "CTmQup3tXKmgr92ECk"
	}
}
```