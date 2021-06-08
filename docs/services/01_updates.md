# Updates
The Dynamite team publishes a set of default configurations and mirrors for each minor release of dynamite-nsm.

To take advantage of any new improvements to the default configuration sets simply run: `sudo dynamite updates install`.
Now the next time you install a new `service` the new default configurations will be applied.
```bash
sudo dynamite updates install -h

usage: dynamite [-h] {install} ...

Update default configurations and mirrors.

positional arguments:
  {install}
    install   Update mirrors and default configurations

optional arguments:
  -h, --help  show this help message and exit
```

## Defaults

### Directories

- Default Configurations: `/etc/dynamite/default_configs/`
- Mirrors: `/etc/dynamite/mirrors/`