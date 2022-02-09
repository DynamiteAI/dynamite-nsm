# Debian 10 Preparation

## Setup Tasks

### Install Python Development Packages

Debian 10 ships with Python 3.7.3 which has been tested extensively by our team.

#### Install Python Development Packages
```bash
sudo apt-get install python3-dev python3-pip
```

#### Make sure `/usr/sbin/` is in your `$PATH`

Debian 10 doesn't include `/usr/sbin/` in the path, causing some of our basic commandline wrappers to fail.

``` bash
sudo su
export PATH="$PATH:/usr/sbin/"
source ~/.bashrc
```
## Install DynamiteNSM Package

### Install DynamiteNSM via PIP

```bash
sudo python3.8 -m pip install dynamite-nsm
```