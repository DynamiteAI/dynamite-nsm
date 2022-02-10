# Kibana

> ⚠️ Changes made within these interfaces require that Kibana be restarted. Typically, the easiest way to 
> accomplish this is via the command:
> `sudo dynamite kibana process restart`


DynamiteNSM exposes only one Kibana related configuration: `main`. 
The `main` configuration provides limited access into several relevant sections of the `kibana.yaml`.

## Main

To display the current `main` configuration options.

```bash
dynamite kibana config main
```

```markdown
╒════════════════════════╤══════════════════════════════════╕
│ Config Option          │ Value                            │
├────────────────────────┼──────────────────────────────────┤
│ host                   │ 192.168.194.143                  │
├────────────────────────┼──────────────────────────────────┤
│ port                   │ 5601                             │
├────────────────────────┼──────────────────────────────────┤
│ elasticsearch_targets  │ ['https://192.168.194.143:9200'] │
├────────────────────────┼──────────────────────────────────┤
│ elasticsearch_username │ kibanaserver                     │
├────────────────────────┼──────────────────────────────────┤
│ elasticsearch_password │ kibanaserver                     │
├────────────────────────┼──────────────────────────────────┤
│ kibana_config_path     │ /etc/dynamite/kibana/kibana.yml  │
╘════════════════════════╧══════════════════════════════════╛
```

To update one or more configuration values:

```bash
sudo dynamite kibana config main --elasticsearch-username kibanaserver --elasticsearch-password "changeme"
```