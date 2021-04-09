---
title: files.log
---
## Zeek `files.log`

An interface for driving the analysis of files, possibly independent of any network protocol over which they’re transported.

### X509 Certificate Exchange

```json
{
	"@timestamp": "2021-01-18T19:58:25.728Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"ephemeral_id": "9b5aa2d4-1b54-4c25-bd2d-61cd592d34f4",
		"type": "filebeat",
		"version": "7.9.2"
	},
	"client": {
		"ip": "192.168.194.128"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"kind": "event",
		"created": "2021-01-18T19:58:34.279540379Z",
		"module": "zeek",
		"id": "C4AHgq1UaIgSiE12C4",
		"category": [
			"file"
		],
		"type": [
			"info"
		],
		"dataset": "zeek.files"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"file": {
		"mime_type": "application/x-x509-user-cert",
		"hash": {
			"sha1": "6d3c6aa45f46eb8bb6fb8f0844020161a025c3c8",
			"md5": "329956dbb75e522e0931d34576914a1d"
		}
	},
	"fileset": {
		"name": "files"
	},
	"host": {
		"name": "sensor-dev"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/files.log"
		},
		"offset": 1077
	},
	"related": {
		"ip": [
			"44.227.11.155",
			"192.168.194.128"
		],
		"hash": [
			"329956dbb75e522e0931d34576914a1d",
			"6d3c6aa45f46eb8bb6fb8f0844020161a025c3c8"
		]
	},
	"server": {
		"ip": "44.227.11.155"
	},
	"service": {
		"type": "zeek"
	},
	"tags": [
		"zeek.files"
	],
	"zeek": {
		"files": {
			"session_ids": [
				"C4AHgq1UaIgSiE12C4"
			],
			"timedout": false,
			"local_orig": false,
			"tx_host": "44.227.11.155",
			"source": "SSL",
			"is_orig": false,
			"overflow_bytes": 0,
			"duration": 0,
			"sha1": "6d3c6aa45f46eb8bb6fb8f0844020161a025c3c8",
			"depth": 0,
			"analyzers": [
				"SHA1",
				"X509",
				"MD5"
			],
			"mime_type": "application/x-x509-user-cert",
			"rx_host": "192.168.194.128",
			"fuid": "F8TQ9LErOrU0jX7i3",
			"seen_bytes": 1766,
			"missing_bytes": 0,
			"md5": "329956dbb75e522e0931d34576914a1d"
		},
		"session_id": "C4AHgq1UaIgSiE12C4"
	}
}
```