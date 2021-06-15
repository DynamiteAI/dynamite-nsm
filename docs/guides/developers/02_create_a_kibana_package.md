# Create a Kibana Package

DynamiteNSM ships with a simple package manager for installing and uninstalling groups Kibana objects.

Packages typically contain searches, visualizations and dashboards combined to facilitate one or more investigatory workflows.

By default, DynamiteNSM will install the `dynamite-investigator` package, which provides a unique blend of host centric and event/alert centric views.

> ⓘ `dynamite kibana package` is still in the early stages of development, and thus likely to change in future releases.

## Checkout Existing Packages
```bash
git clone https://github.com/DynamiteAI/kibana_packages.git
```

## Package Format Guidelines
We've developed a few internal guidelines that must be followed for those wishing to submit their own package to the Dynamite package repository.
They are available [here](https://github.com/DynamiteAI/kibana_packages/blob/main/package_guidelines.md).

## Setting up a Working Environment

Before you can create a new Kibana package you will need to [setup a working monitor and agent instance](/guides/01_quick_start).
Once the agent starts sending events Kibana's discovery view will quickly fill up, and you can begin creating new visualisations and dashboards.

![](/data/img/kibana_discovery.png)

The `dynamite-investigator` package provides some out-of-the-box saved searches, useful for filtering and
differentiating between event types. These searches can serve as a basis for creating your own visualizations and dashboards.

![](/data/img/saved_search_select.png)

## Creating a Visualization
Kibana provides a fairly exhaustive set of visualizations for representing both simple and complex relationships in your data.

You can create a new visualization by double-clicking the `Vizualize` tab in the left-hand sidebar. From there simply select the `Create visualization` button
to enter into the `New Vizualization` interface.

![](/data/img/new_vizualization.png)

## Adding a Visualization to a Dashboard

Dashboards serve as space to present a variety of visualizations that typically share some common theme.
Kibana dashboards provide the ability to enforce certain global constraints against all visualizations within that dashboard.

For example, the `time-range filter` and any `term filters` or `KQL searches` can be applied consistently accross all visualizations within
a dashboard.

To create a new `Dashboard` double-click the `Dashboard` tab in left-hand sidebar. You may then add any vizualization or saved_search you have created.

![](/data/img/create_new_dashboard_viz.png)

## Exporting Saved Objects

To export saved objects simply navigate to `Stack Management` in the left-hand sidebar. From there select `Saved Objects` link.
Within this UI you can export all the objects or just those of a certain type.

We suggest that objects are exported for each type and without including related objects. By doing so other developers can easily build
upon the parts of your package most useful to them. 

![](/data/img/export_saved_object_type.png)

## Creating the Package

Every `kibana package` consists of one or more saved_object.ndjson files and a `manifest.json` file.

The `.ndjson` files are the output of a Kibana export operation as outlined above. A `manifest.json` simply contains
some additional metadata as well as a list of files to be installed via Kibana's saved_object's API.

### manifest.json

```json5
{
	"name": "Baselines",
	"author": "John Doe",
	"author_email": "jdoe@example.com",
	"description": "Includes several base-lining techniques useful for identifying anomalies on small networks",
	"package_type": "saved_objects",
	"file_list": ["config.ndjson", "index_patterns.ndjson", "searches.ndjson", "visualizations.ndjson", "dashboards.ndjson"]

}
```
> **Important!**: The order of appearance in the file_list is important, dependencies should precede their dependants.  

> In the example above `searches.ndjson` relies on or references the data from `index_patterns.ndjson` to be available at installation time, otherwise errors and unexpected behavior may arise.

## Create an Archive

```bash
tar -cvf baselines.tar.gz baselines/*
```