
## Config Selection

```bash
root@jamin-dev:~# dynamite zeek config -h
usage: dynamite config [-h] {site} ...

positional arguments:
  {site}
    site      Configure which Zeek scripts are enabled/disabled.

optional arguments:
  -h, --help  show this help message and exit

```

## Site Config

```bash
usage: dynamite config site [-h] [--configuration-directory CONFIGURATION_DIRECTORY] [--verbose] [--stdout] [--out-file-path OUT_FILE_PATH] [--backup-directory BACKUP_DIRECTORY]
                            {scripts,signatures,definitions} ...

positional arguments:
  {scripts,signatures,definitions}
    scripts
    signatures
    definitions

optional arguments:
  -h, --help            show this help message and exit
  --configuration-directory CONFIGURATION_DIRECTORY
                        The path to the Zeek configuration directory (E.G /etc/dynamite/zeek)
  --verbose             Include detailed debug messages
  --stdout              Print output to console
  --out-file-path OUT_FILE_PATH
                        The path to the output file; if none given overwrites existing
  --backup-directory BACKUP_DIRECTORY
                        The path to the backup directory

```