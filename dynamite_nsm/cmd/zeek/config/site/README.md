## Usage

```bash
usage: zeek config site [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--verbose] [--stdout] [--out-file-path OUT_FILE_PATH] [--backup-directory BACKUP_DIRECTORY] {scripts,signatures,definitions} ...

positional arguments:
  {scripts,signatures,definitions}
    scripts
    signatures
    definitions

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
  --verbose
  --stdout
  --out-file-path OUT_FILE_PATH
                        The path to the output file; if none given overwrites existing
  --backup-directory BACKUP_DIRECTORY

```

### Sub-Configuration Interfaces

#### Definitions

```bash
usage: zeek config site definitions [-h] [--id {6522,3852,6591}] [--enable] [--disable] [--value VALUE]

optional arguments:
  -h, --help            show this help message and exit
  --id {6522,3852,6591}
                        Specify the id for the config object you want to work with.
  --enable              Enable selected object.
  --disable             Disable selected object
  --value VALUE         The value associated with the selected object

```

#### Scripts

```bash
usage: zeek config site scripts [-h]
                                [--id {1144,674,5669,2902,1747,1297,9798,5926,12087,5977,12918,9368,10614,11552,11149,11747,10595,5844,12286,10143,935,6709,3200,13347,14834,5853,2005,1844,20,5250,6107,2317,12563,1346,14668,12997,5821,882,8718,9286,833,5971,11123,9322,39,11791,275,8468,1488,5823,5028,7013,1859,372,9023,3252,11285,6209,8732}]
                                [--enable] [--disable]

optional arguments:
  -h, --help            show this help message and exit
  --id {1144,674,5669,2902,1747,1297,9798,5926,12087,5977,12918,9368,10614,11552,11149,11747,10595,5844,12286,10143,935,6709,3200,13347,14834,5853,2005,1844,20,5250,6107,2317,12563,1346,14668,12997,5821,882,8718,9286,833,5971,11123,9322,39,11791,275,8468,1488,5823,5028,7013,1859,372,9023,3252,11285,6209,8732}
                        Specify the id for the config object you want to work with.
  --enable              Enable selected object.
  --disable             Disable selected object
```

#### Signatures

```bash
usage: zeek config site signatures [-h] [--id {8526}] [--enable] [--disable]

optional arguments:
  -h, --help   show this help message and exit
  --id {8526}  Specify the id for the config object you want to work with.
  --enable     Enable selected object.
  --disable    Disable selected object

```

## Examples

```bash
$ python3 zeek/config/site

╒═══════════════╤══════════════════════╕
│ Config Option │ Value                │
├───────────────┼──────────────────────┤
│ scripts       │ Configuration Module │
├───────────────┼──────────────────────┤
│ signatures    │ Configuration Module │
├───────────────┼──────────────────────┤
│ definitions   │ Configuration Module │
╘═══════════════╧══════════════════════╛

```

```bash
$ python3 zeek/config/site definitions
╒══════╤════════════════════════╤═════════╤════════╕
│ Id   │ Name                   │ Enabled │ Value  │
├──────┼────────────────────────┼─────────┼────────┤
│ 6522 │ ignore_checksums       │ True    │ T;     │
├──────┼────────────────────────┼─────────┼────────┤
│ 3852 │ Stats::report_interval │ True    │ 1mins; │
├──────┼────────────────────────┼─────────┼────────┤
│ 6591 │ Netbase::obs_interval  │ True    │ 5mins; │
╘══════╧════════════════════════╧═════════╧════════╛

```