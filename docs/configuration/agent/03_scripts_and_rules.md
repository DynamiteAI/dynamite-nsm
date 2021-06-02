# Scripts and Rules

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

> ⓘ Changes made within these interfaces require that Zeek and/or Suricata be restarted. Typically, the easiest way to 
> accomplish this is via the command:
> `sudo dynamite agent process restart`

### Zeek

You can list all the available scripts with the below command. Note the `Id` column as these can be used for selection.
```bash
sudo dynamite zeek config site scripts
```

> Alternatively, advanced users may wish to interact directly with the configuration file. If installed with default options
it can be found here: `/etc/dynamite/zeek/site/local.zeek`

Users enumerate choice scripts by specifying their `--ids`

```bash
sudo dynamite zeek config site scripts --ids 5926 372 275 5823
```

```markdown
╒══════╤═════════════════════════════════════════╤═══════════╤═════════╕
│   Id │ Name                                    │ Enabled   │ Value   │
╞══════╪═════════════════════════════════════════╪═══════════╪═════════╡
│ 5926 │ policy/protocols/conn/mac-logging       │ True      │ N/A     │
├──────┼─────────────────────────────────────────┼───────────┼─────────┤
│  275 │ frameworks/dpd/detect-protocols         │ True      │ N/A     │
├──────┼─────────────────────────────────────────┼───────────┼─────────┤
│ 5823 │ frameworks/files/entropy-test-all-files │ False     │ N/A     │
├──────┼─────────────────────────────────────────┼───────────┼─────────┤
│  372 │ Zeek_AF_Packet/scripts                  │ True      │ N/A     │
╘══════╧═════════════════════════════════════════╧═══════════╧═════════╛
```

Enabling and disabling Zeek Scripts can be done simply by adding an `--enable` or `--disable` flag.

```bash
sudo dynamite zeek config site scripts --ids 5926 275 5823 --disable
```

### Suricata

Suricata's rule interface functions almost exactly as Zeek's. To list all available Suricata rules use the below command.

```bash
sudo dynamite suricata config main rules
```

Specific `--ids` can also be selected and enabled or disabled.

```bash
sudo dynamite suricata config main rules --ids 9007 2857 4409 --enable
```

```markdown
╒══════╤═══════════════════════╤═══════════╤═════════╕
│   Id │ Name                  │ Enabled   │ Value   │
╞══════╪═══════════════════════╪═══════════╪═════════╡
│ 4409 │ emerging-telnet.rules │ True      │ N/A     │
├──────┼───────────────────────┼───────────┼─────────┤
│ 2857 │ dns-events.rules      │ True      │ N/A     │
├──────┼───────────────────────┼───────────┼─────────┤
│ 9007 │ tls-events.rules      │ True      │ N/A     │
╘══════╧═══════════════════════╧═══════════╧═════════╛
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
