# AlmaLinux 8 Preparation

## Setup Tasks

### Install Python3.8

For AlmaLinux 8, we suggest users use Python3.8 which has been tested extensively by our team.

#### Install Required Dependencies
```bash
dnf remove python3 python3-pip
dnf module install python3.8
dnf install python38-devel
```

#### Download Python 3.8.3

```bash
wget https://www.python.org/ftp/python/3.8.3/Python-3.8.3.tgz
```

#### Compile from Source

```bash
tar xvf Python-3.8.3.tgz
cd Python-3.8*/
./configure --enable-optimizations --enable-loadable-sqlite-extensions
sudo make altinstall
```

## Install DynamiteNSM Package

### Locate Python 3.8

```bash
whereis python3.8
```

### Install DynamiteNSM via PIP

```bash
sudo python3.8 -m pip install dynamite-nsm
```