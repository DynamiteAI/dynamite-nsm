# Kibana Dashboards

DynamiteNSM relies on Kibana for visualization. These visualizations can be broken down into five main modules:

1. **Events**  The event module is the heart of the Dynamite Network Monitor this module is meant to provide a central place for a variety of network relationships. These dashboards work both with our agent and Netflow exporters.

2. **Alerts** The alert module relies on the Suricata analyzer function available within the agent. signature-based detections are available from the open [Emerging Threat Rule Sets](https://rules.emergingthreats.net/).

3. **Files** The file module relies on Zeeks files framework and contains metadata about files and certificates transferred over protocols such as HTTP, FTP, and SSL.

4. **Baselines** are available only to users who install our agent. They take advantage of the Zeek based [Netbase](https://github.com/pmphry/netbase) scripts. These scripts snapshot local assets on a set interval and record relevant metrics ([documented here](https://dynamite-sdk-lite.s3-us-west-2.amazonaws.com/dynamite_sdk/objects/baselines.html#the-interval)). 

5. **Statistics** capture information about the current deployment. There are three kinds of statistic dashboards: 
   - Agent-based statistics for both Zeek and Suricata, which record metrics like average memory consumption.
   - NetFlow based statistics for users who take advantage of NetFlow + Agent  hybrid deployments
   
## Additional Reading

- [Events](kibana_dashboards/event_dashboards.md)
- [Alerts](kibana_dashboards/alert_dashboards.md)
- [Files](kibana_dashboards/files_dashboards.md)
- [Baselines <sub>Experimental</sub>](kibana_dashboards/baseline_dashboards.md)
- [Statistics Dashboard](kibana_dashboards/statistics_dashboards.md)