# dynamite_nsm.package_manager

## OSPackageManager
```python
OSPackageManager(self)
```

Interface for interacting with the operating systems package manager system
Currently supports YUM/apt-get

### detect_package_manager
```python
OSPackageManager.detect_package_manager()
```

Detect the POSIX package manager currently being used
:return: The package manager command

### install_packages
```python
OSPackageManager.install_packages(self, packages)
```

Given a set of packages, installs the packages

:param packages: Name of binary packages to install

### refresh_package_indexes
```python
OSPackageManager.refresh_package_indexes(self)
```

Refresh the package cache

