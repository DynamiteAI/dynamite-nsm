# Install on Same Instance

> ⚠️ If you ever change the number of CPU cores or inspection interfaces on an agent instance simply run: `dynamite agent optimize --inspect-interfaces <int1f> <intf2>...` to automatically adjust
> CPU-affinity and threading families.

## Update Default Configs and Mirrors
Make sure you have the latest default configurations and mirrors for the version of DynamiteNSM you have installed.
```bash
sudo dynamite updates install
```

## Install Using the Agent Service
DynamiteNSM provides a convenience `service` called `agent` which bundles `zeek`, `suricata`, and `filebeat` services
into a single deployment.


In the below example traffic on the interfaces `eth0` `eth1` and `eth3` will be monitored; results will be sent to an `elasticsearch` instance to the url: `https://dynamite-monitor:9200`.

```bash
sudo dynamite agent install --inspect-interfaces eth0 eth1 eth2 --targets https://dynamite-monitor:9200
```

## Start the Processes
Once installed, you can start the process and check its status using the below commands.

```bash
sudo dynamite agent process start
sudo dynamite agent process status
```


## Check the Logs

Once Filebeat has successfully started, you can see how many events were sent to Elasticsearch.

```bash
sudo dynamite filebeat logs metrics
```

If Filebeat is not started or events are not populating downstream check the Filebeat log file or tail the summary with the below command.

```bash
sudo dynamite filebeat logs main
```