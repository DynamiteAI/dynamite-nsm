# Install on Same Instance


## Update Default Configs and Mirrors

Make sure you have the latest default configurations and mirrors for the version of DynamiteNSM you have installed.
```bash
sudo dynamite updates install
```

## Install Using the Monitor Service

Install Elasticsearch and Kibana with several security features enabled and Dynamite's default [Kibana packages installed](../../../guides/base_views/01_overview).

Both services will listen on the primary interface (default route). 

```bash
sudo dynamite monitor install
```

## Start the Processes

Once installed, you can check the process using the below command.

```bash
sudo dynamite monitor process status
```
