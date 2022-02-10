 <!-- ## *DISCOVER YOUR NETWORK* -->

<p align="center">
 <a href="http://dynamite.ai"><img src="https://github.com/vlabsio/dynamite-nsm/raw/master/img/dynamite_analytics.png" width="400" height="auto"></a>
</p>

---
### What is Dynamite Network Security Monitor?
DynamiteNSM is a lightweight network security monitor conveniently bundled as a `Python ≥3.7` package. 
Built initially to simplify the installation of [Zeek](https://zeek.org/) and [Suricata](https://suricata.io/), the package now includes a robust set of Python modules for installing and managing both network monitoring and data visualization services.

However, you do not need to write a single line of code to begin using DynamiteNSM. 
The package comes with a commandline utility that automates the deployment of passive, packet-sniffing `agents` throughout your network, along with a `monitor` for visualizing the events produced by them. 

You can install the `dynamite-nsm` package via `pip3` on any one of these supported [Linux distributions](https://dynamiteai.github.io/dynamite-nsm/requirements/01_supported_operating_systems). 

```bash
sudo pip3 install dynamite-nsm
```

<center>
    <img src="docs/data/img/demos/intro.gif">
</center>


[**Quick Start Guide »**](https://dynamiteai.github.io/dynamite-nsm/guides/01_quick_start)


### Dashboards

DynamiteNSM's `monitor` component ships with a powerful set of dashboards for finding patterns in your network data.

<center>
    <img src="docs/data/img/kibana_dashboard_alerts.png">
</center>

[**Dashboard Overview »**](https://dynamiteai.github.io/dynamite-nsm/guides/base_views/01_overview)



### Documentation

Checkout our comprehensive documentation complete with tutorials, guides, and example quickstart deployments.

Those wishing to contribute may also be interested in our [development guides](https://dynamiteai.github.io/dynamite-nsm/guides/developers/01_overview).

[**Read the Documentation »**](https://dynamiteai.github.io/dynamite-nsm/)


