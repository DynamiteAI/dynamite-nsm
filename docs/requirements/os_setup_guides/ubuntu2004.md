# Ubuntu 20.04 Preparation

## Setup Tasks

### Install Python Development Tools

Python3 should already be installed by default on this version of Ubuntu, however you will need to install
a few tools to install `dynamite-nsm` package.

``` bash
sudo apt-get install python3-dev python3-pip
```
## Install DynamiteNSM Package

### Locate Python 3.8

```bash
whereis python3.8
```

### Install DynamiteNSM via PIP

```bash
sudo python3 -m pip install dynamite-nsm
```