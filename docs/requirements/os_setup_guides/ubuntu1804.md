# Ubuntu 18.04 Preparation

## Setup Tasks

### Install Python3.8

For Ubuntu 18.04, we suggest users use Python3.8 which has been tested extensively by our team.

#### Install the Deadsnakes Repository
```bash
sudo apt-get update
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa
```

#### Install Python and Development Tools

``` bash
sudo apt-get install python3.8-dev python3.8-pip
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