## Install on Same Instance

Make sure you have the latest default configurations and mirrors for the version of DynamiteNSM you have installed.
```bash
sudo dynamite updates install
```

Install Zeek and Suricata along with Filebeat. In the below example traffic on the interfaces `eth0` `eth1` and `eth3` will be monitored;
results will be sent to an `elasticsearch` instance to the url: `https://dynamite-monitor:9200`.

```bash
sudo dynamite agent install --inspect-interfaces eth0 eth1 eth2 --target https://dynamite-monitor:9200
```

Once installed, you can check the process using the below command.

```bash
sudo dynamite agent process status
```

Once Filebeat has successfully started, you can see how many events were sent to Elasticsearch.

```bash
sudo dynamite filebeat logs metrics
```