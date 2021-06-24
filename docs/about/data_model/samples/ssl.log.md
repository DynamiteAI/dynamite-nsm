---
title: ssl.log
---

## Zeek `ssl.log`
SSL/TLS handshake info

### Failed to Establish TLS Session
```json
{
	"@timestamp": "2021-01-18T19:19:19.760Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"ephemeral_id": "9b5aa2d4-1b54-4c25-bd2d-61cd592d34f4",
		"type": "filebeat",
		"version": "7.9.2"
	},
	"client": {
		"address": "127.0.0.1"
	},
	"destination": {
		"address": "127.0.0.1",
		"port": 47763,
		"ip": "127.0.0.1"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"kind": [
			"connection",
			"protocol"
		],
		"created": "2021-01-18T19:35:11.917623174Z",
		"module": "zeek",
		"id": "CgJFJV0S7TpYJkc1e",
		"category": [
			"network"
		],
		"dataset": "zeek.ssl"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"fileset": {
		"name": "ssl"
	},
	"host": {
		"name": "sensor-dev"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/ssl.log"
		},
		"offset": 0
	},
	"network": {
		"community_id": "1:MIn0vYshYL45/ZjBgofGuA/a4fY=",
		"transport": "tcp"
	},
	"related": {
		"ip": [
			"127.0.0.1",
			"127.0.0.1"
		]
	},
	"server": {
		"address": "127.0.0.1"
	},
	"service": {
		"type": "zeek"
	},
	"source": {
		"address": "127.0.0.1",
		"port": 60872,
		"ip": "127.0.0.1"
	},
	"tags": [
		"zeek.ssl"
	],
	"tls": {
		"cipher": "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA",
		"established": false,
		"curve": "secp384r1",
		"resumed": false,
		"version": "1.2",
		"version_protocol": "tls"
	},
	"zeek": {
		"session_id": "CgJFJV0S7TpYJkc1e",
		"ssl": {
			"cipher": "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA",
			"established": false,
			"community_id": "1:MIn0vYshYL45/ZjBgofGuA/a4fY=",
			"curve": "secp384r1",
			"resumed": false,
			"version": "TLSv12"
		}
	}
}
```