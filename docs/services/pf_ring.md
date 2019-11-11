# dynamite_nsm.services.pf_ring

## PFRingInstaller
```python
PFRingInstaller(self, install_directory='/opt/dynamite/pf_ring/')
```

An interface for installing PF_RING kernel module and UserLand requirements

### download_pf_ring
```python
PFRingInstaller.download_pf_ring(stdout=False)
```

Download PF_RING archive

:param stdout: Print output to console

### extract_pf_ring
```python
PFRingInstaller.extract_pf_ring(stdout=False)
```

Extract PF_RING to local install_cache

:param stdout: Print output to console

### install_dependencies
```python
PFRingInstaller.install_dependencies()
```

Install required PF_RING dependencies

:return: True, if packages were successfully installed

### setup_pf_ring
```python
PFRingInstaller.setup_pf_ring(self, stdout=False)
```

Compile and setup required binaries and kernel modules

:param stdout: Print output to console

## PFRingProfiler
```python
PFRingProfiler(self, stderr=False)
```

An Interface for determining whether PF_RING is installed/configured/running properly.

