# Centos 7 Setup Guide

## Setup Tasks

### Install Python3.8

For CentOS 7, we suggest users use Python3.8 which has been tested extensively by our team.

#### Install Required Dependencies
```bash
sudo yum -y update
sudo yum -y groupinstall "Development Tools"
sudo yum -y install gcc gcc-c++ openssl-devel bzip2-devel libffi-devel wget
```

#### Download Python 3.8.3

```bash
wget https://www.python.org/ftp/python/3.8.3/Python-3.8.3.tgz
```

#### Compile from Source

```bash
tar xvf Python-3.8.3.tgz
cd Python-3.8*/
./configure --enable-optimizations
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