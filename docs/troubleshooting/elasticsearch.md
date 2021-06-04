# Elasticsearch

### Elasticsearch won't start

**Symptoms**: You have started `elasticsearch` via the commandline utility or `systemctl` you wait 30 seconds and run the 
`sudo dynamite elasticsearch process status` command, and receive the following.

```markdown
╒════════════════════╤═════════════════════════════════════════════╕
│ Service            │ elasticsearch.process                       │
├────────────────────┼─────────────────────────────────────────────┤
│ Running            │ no                                          │
├────────────────────┼─────────────────────────────────────────────┤
│ Enabled on Startup │ yes                                         │
├────────────────────┼─────────────────────────────────────────────┤
│ Logs               │ /var/log/dynamite/elasticsearch/            │
├────────────────────┼─────────────────────────────────────────────┤
│ Command            │ sudo systemctl status elasticsearch.service │
├────────────────────┼─────────────────────────────────────────────┤
│ Exit Code          │ 3                                           │
╘════════════════════╧═════════════════════════════════════════════╛
```

| Problem          | Description                                                                                                                                                                                                                           | Solution                                                                                                                                                                                                                                                                                                                                                                                               |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Out of Memory    | `elasticsearch` needs to be able to provision a certain amount of heap space (memory) at runtime.  As the document store grows, various operations become more memory intensive and can prevent `elasticsearch` from starting         | Check the `/var/log/dynamite/elasticsearch/dynamite-cluster.log` for a message resembling the following: `There is insufficient memory for the Java Runtime Environment to continue.` If an entry like this is found you must increase the amount of memory on the machine. `sudo systemctl status elasticsearch` or `sudo dynamite elasticsearch process status --verbose` may also provide insights. |
| Misconfiguration | The `elasticsearch.yaml` controls the behavior of `elasticsearch` at runtime. It conforms to `yaml` format. If an invalid value is given or the `yaml` specification violated an error will be logged and `elasticsearch` will crash. | Use a tool like [yamlint](https://github.com/adrienverge/yamllint#installation) to identify obvious issues. Check the Check the  `/var/log/dynamite/elasticsearch/dynamite-cluster.log` for misconfiguration hints.                                                                                                                                                                                    |
