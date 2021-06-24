# Configuration Overview
The `dynamite` commandline utility exposes convenient wrappers around installed `services`.

## Commandline Tips
The `dynamite` commandline is modular by design. You add run the `-h` argument at any time to get `usage` information about the currently selected module.

For example, `sudo dynamite -h` will give you general information about the top-level services, and the actions
that can be performed against each.

```bash
positional arguments:
  {agent,monitor,zeek,suricata,filebeat,elasticsearch,logstash,kibana,updates,remote}
                        A component within the Dynamite stack to manage.
  {install,uninstall,config,logs,process}
                        An action or set of actions that can be performed against a specified component.

optional arguments:
  -h, --help            show this help message and exit
```

You can get usage information about a specific service such as `elasticsearch` by running`sudo dynamite elasticsearch -h`

```bash
usage: dynamite [-h] {install,uninstall,process,config} ...

Elasticsearch @ 192.168.194.143

positional arguments:
  {install,uninstall,process,config}
    install             Install Elasticsearch as a standalone component.
    uninstall           Uninstall Elasticsearch on this machine.
    process             Manage local Elasticsearch node processes.
    config              Modify Elasticsearch configurations.

optional arguments:
  -h, --help            show this help message and exit
```

## Navigating Service Configs

At any time simply typing `sudo dynamite` will generate a table similar to the one below which installed and running services.
```markdown
╒═══════════════╤═════════════╤═══════════╤════════════════╕
│ Service       │ Installed   │ Running   │ Service Role   │
╞═══════════════╪═════════════╪═══════════╪════════════════╡
│ elasticsearch │ X           │ X         │ Monitor        │
├───────────────┼─────────────┼───────────┼────────────────┤
│ logstash      │ X           │ X         │ Monitor        │
├───────────────┼─────────────┼───────────┼────────────────┤
│ kibana        │ X           │ X         │ Monitor        │
├───────────────┼─────────────┼───────────┼────────────────┤
│ zeek          │ ✓           │ X         │ Agent          │
├───────────────┼─────────────┼───────────┼────────────────┤
│ suricata      │ ✓           │ X         │ Agent          │
├───────────────┼─────────────┼───────────┼────────────────┤
│ filebeat      │ ✓           │ ✓         │ Agent          │
╘═══════════════╧═════════════╧═══════════╧════════════════╛
```

Some services have multiple config interfaces. To list available ones check the services as below.
Elasticsearch for example has two configs accessible config interfaces: `java` and `main`.

```bash
$ sudo dynamite elasticsearch config -h

usage: dynamite config [-h] {main,java} ...

positional arguments:
  {main,java}
    main       Configure Elasticsearch on this machine.
    java       Configure Java heap allocation for Elasticsearch on this machine.

optional arguments:
  -h, --help   show this help message and exit
```

You can view a configuration simply by appending the name of the sub-menu to the `config` command.

```bash
$ sudo dynamite elasticsearch config java
```

```markdown
╒════════════════╤═══════╕
│ Config Option  │ Value │
├────────────────┼───────┤
│ initial_memory │ 8g    │
├────────────────┼───────┤
│ maximum_memory │ 8g    │
╘════════════════╧═══════╛
```

Most configurations are key-value pair based, and allow you to specify a list of arguments and their values.

```bash
sudo dynamite elasticsearch config java --initial-memory 12g --maximum-memory 12g
```

## Configuration Modules

If you run a command like `sudo dynamite filebeat config main` you'll be given a table like this:

```markdown
╒═══════════════════════╤══════════════════════╕
│ Config Option         │ Value                │
├───────────────────────┼──────────────────────┤
│ elasticsearch_targets │ Configuration Module │
├───────────────────────┼──────────────────────┤
│ logstash_targets      │ Configuration Module │
├───────────────────────┼──────────────────────┤
│ kafka_targets         │ Configuration Module │
├───────────────────────┼──────────────────────┤
│ redis_targets         │ Configuration Module │
╘═══════════════════════╧══════════════════════╛
```

The `Configuration Module` value simply means that you can access the `Config Object` as a sub-menu.

```bash
$ sudo dynamite filebeat config main redis_targets -h

usage: dynamite config main redis_targets [-h] [--target-strings TARGET_STRINGS [TARGET_STRINGS ...]] [--ssl-certificate-authorities SSL_CERTIFICATE_AUTHORITIES [SSL_CERTIFICATE_AUTHORITIES ...]]
                                          [--ssl-certificate SSL_CERTIFICATE] [--ssl-key SSL_KEY] [--ssl-verification-mode SSL_VERIFICATION_MODE] [--index INDEX] [--socks-5-proxy-url SOCKS_5_PROXY_URL]
                                          [--workers WORKERS] [--max-batch-size MAX_BATCH_SIZE] [--db DB] [--load-balance] [--password PASSWORD] [--enable] [--disable]

optional arguments:
  -h, --help            show this help message and exit

target options:
  --target-strings TARGET_STRINGS [TARGET_STRINGS ...]
                        A list of Redis hosts, and their service port (E.G ["192.168.0.9 6379"]
  --ssl-certificate-authorities SSL_CERTIFICATE_AUTHORITIES [SSL_CERTIFICATE_AUTHORITIES ...]
                        The list of root certificates for server verifications.
  --ssl-certificate SSL_CERTIFICATE
                        The path to the certificate for SSL client authentication.
  --ssl-key SSL_KEY     The client certificate key used for client authentication.
  --ssl-verification-mode SSL_VERIFICATION_MODE
                        This option controls whether the client verifies server certificates and host names.
  --index INDEX         The key format string to use.
  --socks-5-proxy-url SOCKS_5_PROXY_URL
                        The full url to the SOCKS5 proxy used for encapsulating the beat protocol
  --workers WORKERS     The number of workers to use for each host configured to publish events to Redis.
  --max-batch-size MAX_BATCH_SIZE
                        The maximum number of events to bulk in a single Redis request or pipeline.
  --db DB               The Redis database number where the events are published. The default is 0.
  --load-balance        If included and multiple Redis hosts are configured load-balance between them
  --password PASSWORD   The password to authenticate with. The default is no authentication.
  --enable              Enable selected target.
  --disable             Disable selected target
```