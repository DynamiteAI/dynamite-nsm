# Scripts and Rules

> ⚠️ Changes made within these interfaces require that Zeek and/or Suricata be restarted. Typically, the easiest way to 
> accomplish this is via the command:
> `sudo dynamite agent process restart`

Both Zeek and Suricata provide unique methods for 
extracting information from raw network traffic and building detections.

Zeek ships with an event-driven scripting language that gives end-users direct access to traffic flowing over the wire.
Zeek Scripts can be used to accomplish anything from protocol parsing to 
alerting on suspicious activity. 

Suricata is a more conventional intrusion detection system. Suricata's rules-engine is capable of 
extremely fast pattern matching, and is excellent for identifying known malicious activity. 

## Working with Scripts and Rules

The `dynamite` commandline utility provides a relatively simple interface for 
enabling disabling scripts and rules. 

### Zeek

You can list all the available scripts with the below command. Note the `Id` column as these can be used for selection.
```bash
dynamite zeek config site scripts
```

> Alternatively, advanced users may wish to interact directly with the configuration file. If installed with default options
it can be found here: `/etc/dynamite/zeek/site/local.zeek`

Users enumerate choice scripts by specifying their `--ids`

```bash
dynamite zeek config site scripts --ids 0fd1658 20d7e67 2878963 99e00b3
```

```markdown
╒═════════╤═════════════════════════════════════════════════╤═══════════╤═════════╕
│ Id      │ Name                                            │ Enabled   │ Value   │
╞═════════╪═════════════════════════════════════════════════╪═══════════╪═════════╡
│ 99e00b3 │ protocols/ssh/detect-bruteforcing               │ True      │ N/A     │
├─────────┼─────────────────────────────────────────────────┼───────────┼─────────┤
│ 2878963 │ protocols/ssl/log-hostcerts-only                │ True      │ N/A     │
├─────────┼─────────────────────────────────────────────────┼───────────┼─────────┤
│ 0fd1658 │ policy/frameworks/notice/extend-email/hostnames │ True      │ N/A     │
├─────────┼─────────────────────────────────────────────────┼───────────┼─────────┤
│ 20d7e67 │ packages/cve-2021-44228.git                     │ False     │ N/A     │
╘═════════╧═════════════════════════════════════════════════╧═══════════╧═════════╛
```

Enabling and disabling Zeek Scripts can be done simply by adding an `--enable` or `--disable` flag.

```bash
dynamite zeek config site scripts --ids 0fd1658 20d7e67 2878963 99e00b3 --disable
```

### Suricata

Suricata's rule interface functions almost exactly as Zeek's. To list all available Suricata rules use the below command.

```bash
dynamite suricata config main rules
```

Specific `--ids` can also be selected and enabled or disabled.

```bash
dynamite suricata config main rules --ids 1aeb6e4 e649d09 0bbab15 bdfac29 --enable
```

```markdown
╒═════════╤═══════════════════════════════╤═══════════╤═════════╕
│ Id      │ Name                          │ Enabled   │ Value   │
╞═════════╪═══════════════════════════════╪═══════════╪═════════╡
│ bdfac29 │ ciarmy.rules                  │ True      │ N/A     │
├─────────┼───────────────────────────────┼───────────┼─────────┤
│ 0bbab15 │ emerging-scada.rules          │ False     │ N/A     │
├─────────┼───────────────────────────────┼───────────┼─────────┤
│ e649d09 │ tls-events.rules              │ False     │ N/A     │
├─────────┼───────────────────────────────┼───────────┼─────────┤
│ 1aeb6e4 │ emerging-mobile_malware.rules │ False     │ N/A     │
╘═════════╧═══════════════════════════════╧═══════════╧═════════╛
```

> Advanced users can find the `suricata.yaml` configuration at `/etc/dynamite/suricata/suricata.yaml` assuming 
> default options have not been changed.

### Updating Suricata Rules

We leverage [Open Emerging Threat Signatures](https://rules.emergingthreats.net/) to identify the latest malicious attacks. 
To update your ruleset simply run:

```bash
sudo dynamite suricata update
```

> By default, DynamiteNSM will install a `root` user `cronjob` that runs twice daily to update these rule-sets.
