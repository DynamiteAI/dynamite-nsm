---
title: http.log
---
## Zeek `http.log`

HTTP requests and replies

### POST Request with Response 

```json
{
	"@timestamp": "2021-01-18T19:58:25.832Z",
	"agent": {
		"hostname": "sensor-dev",
		"name": "sensor-dev",
		"id": "6bf5192e-e2f1-49bb-ab7a-c04c26381e7e",
		"ephemeral_id": "9b5aa2d4-1b54-4c25-bd2d-61cd592d34f4",
		"type": "filebeat",
		"version": "7.9.2"
	},
	"destination": {
		"geo": {
			"continent_name": "North America",
			"country_iso_code": "US",
			"country_name": "United States",
			"location": {
				"lon": -97.822,
				"lat": 37.751
			}
		},
		"as": {
			"number": 15133,
			"organization": {
				"name": "MCI Communications Services, Inc. d/b/a Verizon Business"
			}
		},
		"address": "72.21.91.29",
		"port": 80,
		"ip": "72.21.91.29"
	},
	"ecs": {
		"version": "1.5.0"
	},
	"event": {
		"kind": "event",
		"created": "2021-01-18T19:58:34.280666497Z",
		"module": "zeek",
		"action": "post",
		"id": "CMcIc31sqwZSUKQP5j",
		"category": [
			"network",
			"web"
		],
		"type": [
			"connection",
			"info",
			"protocol"
		],
		"dataset": "zeek.http",
		"outcome": "success"
	},
	"fields": {
		"originating_agent_tag": "sensordev_agt"
	},
	"fileset": {
		"name": "http"
	},
	"host": {
		"name": "sensor-dev"
	},
	"http": {
		"request": {
			"method": "POST",
			"body": {
				"bytes": 83
			}
		},
		"response": {
			"status_code": 200,
			"body": {
				"bytes": 471
			}
		},
		"version": "1.1"
	},
	"input": {
		"type": "log"
	},
	"log": {
		"file": {
			"path": "/opt/dynamite/zeek/logs/current/http.log"
		},
		"offset": 2984
	},
	"network": {
		"community_id": "1:V7YJnKQL1/XSRE6bx4UxmzX5NnA=",
		"transport": "tcp"
	},
	"related": {
		"ip": [
			"192.168.194.128",
			"72.21.91.29"
		]
	},
	"service": {
		"type": "zeek"
	},
	"source": {
		"address": "192.168.194.128",
		"port": 34942,
		"ip": "192.168.194.128"
	},
	"tags": [
		"zeek.http"
	],
	"url": {
		"original": "/",
		"port": 80,
		"domain": "ocsp.digicert.com"
	},
	"user_agent": {
		"original": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
		"os": {
			"name": "Ubuntu"
		},
		"name": "Firefox",
		"device": {
			"name": "Other"
		},
		"version": "84.0."
	},
	"zeek": {
		"http": {
			"uri_vars": [
				"/"
			],
			"resp_mime_types": [
				"application/ocsp-response"
			],
			"client_header_names": [
				"HOST",
				"USER-AGENT",
				"ACCEPT",
				"ACCEPT-LANGUAGE",
				"ACCEPT-ENCODING",
				"CONTENT-TYPE",
				"CONTENT-LENGTH",
				"CONNECTION"
			],
			"community_id": "1:V7YJnKQL1/XSRE6bx4UxmzX5NnA=",
			"trans_depth": 1,
			"orig_fuids": [
				"FHbW6v2ACWtzPXSmn2"
			],
			"status_msg": "OK",
			"orig_mime_types": [
				"application/ocsp-request"
			],
			"tags": [],
			"resp_fuids": [
				"F8IRy32mB5ft7uqVx"
			]
		},
		"session_id": "CMcIc31sqwZSUKQP5j"
	}
}
```