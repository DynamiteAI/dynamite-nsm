# dynamite_nsm.services.oinkmaster

## OinkmasterInstaller
```python
OinkmasterInstaller(self, install_directory='/opt/dynamite/oinkmaster/')
```

An interface for installing OinkMaster Suricata update script

### download_oinkmaster
```python
OinkmasterInstaller.download_oinkmaster(stdout=False)
```

Download Oinkmaster archive

- *param* stdout: Print output to console

### extract_oinkmaster
```python
OinkmasterInstaller.extract_oinkmaster(stdout=False)
```

Extract Oinkmaster to local install_cache

- *param* stdout: Print output to console

## update_suricata_rules
```python
update_suricata_rules()
```

Update Suricata rules specified in the oinkmaster.conf file

- *return* True if succeeded

