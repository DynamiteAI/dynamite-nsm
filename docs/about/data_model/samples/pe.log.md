---
title: pe.log
---
## Zeek `pe.log`
Information about Portable Executable (PE) extracted from various application layer protocols.

### Windows Executable (Extracted from HTTP transaction)

```json
{
	"@timestamp": "2021-01-18T20:33:50.188Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"type": "filebeat",
		"ephemeral_id": "9b5aa2d4-1b54-4c25-bd2d-61cd592d34f4",
		"version": "7.9.2"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"kind": "event",
		"created": "2021-01-18T20:33:55.433112556Z",
		"module": "zeek",
		"type": [
			"info"
		],
		"category": [
			"file"
		],
		"dataset": "zeek.pe"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"fileset": {
		"name": "pe"
	},
	"host": {
		"name": "sensor-dev"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/pe.log"
		},
		"offset": 0
	},
	"service": {
		"type": "zeek"
	},
	"tags": [
		"zeek.pe"
	],
	"zeek": {
		"pe": {
			"compile_time": "2006-04-29T09:56:31.000Z",
			"uses_aslr": false,
			"os": "Windows 95 or NT 4.0",
			"subsystem": "WINDOWS_GUI",
			"section_names": [
				".text",
				".rdata",
				".data",
				".rsrc"
			],
			"has_export_table": false,
			"uses_dep": false,
			"is_64bit": false,
			"has_cert_table": true,
			"has_debug_data": false,
			"has_import_table": true,
			"uses_seh": true,
			"is_exe": true,
			"machine": "I386",
			"id": "FnhRQ63qMsSOfIGoWl",
			"uses_code_integrity": false
		}
	}
}
```