<a href="http://dynamite.ai"><img src="https://github.com/vlabsio/dynamite-nsm/raw/master/img/dynamite_analytics.png" width="350" height="auto"></a>
## Dynamite Mirrors and Configurations


Every release cycle, the Dynamite team publishes a corresponding set of configurations and mirrors used for setting up various components of DynamiteNSM.

### What's in the Box?

#### Default Configurations

These configurations are applied, at install time, to the various installable DynamiteNSM components.

| File/Directory | Description                                                                                                                                                                                                                     |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| .constants     | This file contains various parameters that are applied globally at component install time.                                                                                                                                      |
| dynamite_lab/  | Contains the `jupyterhub_config.py` used for the initial setup of JupyterHub                                                                                                                                                    |
| dynamited/     | Contains configurations for the setup of the `dynamited`                                                                                                                                                                        |
| elasticsearch/ | Contains a default `elasticsearch.yml` file used for initial setup of each elasticsearch node.                                                                                                                                  |
| filebeat/      | Contains a default `filebeat.yml` file used for initial setup of the FileBeat log forwarder.                                                                                                                                    |
| kibana/        | Contains a default `kibana.yml` file, as well as an `objects/` directory for installing pre-built Kibana objects.                                                                                                               |
| logstash/      | Contains a `logstash.yml` file, a `pipelines.yml` for initial message routing. Also contains suricata/ zeek/ configuration directories.                                                                                         |
| suricata/      | Contains a `suricata.yaml` file used for the initial setup of Suricata IDS.                                                                                                                                                     |
| systemd/       | Contains a collection of `.service` files and `.target` files used by the systemd subsystem.                                                                                                                                    |
| zeek/          | Contains a default `broctl-nodes.cfg` To setup various Zeek cluster components, and a `local.zeek` file describing enabled scripts and definitions. This directory also contains plugins and scripts to be installed with Zeek. |

#### Mirrors
These mirrors represent locations where required DynamiteNSM components are downloaded. Each file contains a list of URLs where the corresponding package can be downloaded.


### Commandline

```
usage: deploy-configurations.py [-h] [--merge-directory MERGE_DIRECTORY] [--overwrite] base_directory version

Stage Dynamite Configurations to public S3 bucket.

positional arguments:
  base_directory        The path to the directory containing the base configurations.
  version               The version number for the current configuration set.

optional arguments:
  -h, --help            show this help message and exit
  --merge-directory MERGE_DIRECTORY
                        A directory containing additional/modified configurations you want to merge with the base directory and incorporate into the deployment
  --overwrite           If true overwrites an old version if one is specified.

```

Included in this repo is the `deploy-configurations.py` script. Simply run `pip install -r requirements.txt` to grab the dependencies. This script also requires you have `Python3.4+` installed.

#### config.yml
You **must** include a file called in the same directory as `deploy-configurations.py` this file has the following format:

```
[AWS]
aws_access_key_id = <AWS_KEY_ID>
aws_secret_access_key = <AWS_SECRET_ACCESS_KEY>

[S3]
staging_bucket=<config-staging-bucket>
staging_prefix=<config-staging-prefix>
```

#### Example Commandline

```
python3 deploy-configurations.py base_config_set/ 0.73
```

The result will publish `mirrors.tar.gz` and `default_configs.tar.gz` to `$config-staging-bucket/#config-staging-prefix/0.73` with **PUBLIC READ** permissions. Note that the `staging_bucket` **must** be created in advance.


```
python3 deploy-configurations.py base_config_set/ 0.73 --overwrite
```

By default,  this tool will not allow you to overwrite previous configurations in the same `config-staging-prefix`. However, you can force an overwrite on by using the `--overwrite` flag.

```
python3 deploy-configurations.py base_config_set/ 0.73 --merge-directory=config_deltas/logstash_docker_kafka_config_set_delta/
```

If the `--merge-directory` is set that directory will automatically be merged into the $base_directory. In this case `logstash_docker_kafka_config_set_delta/` replicates only the additions/modifications to the `base_config_set/` we want to make.

In other words the`config_deltas/logstash_docker_kafka_config_set_delta/` directory contains only files/directories it wants to create/overwrite. This utility uses `md5hash` comparisons to automatically exclude duplications. 

\* *Note that including this flag will not make any changes to either of the directories referenced in the above command. These changes are made in memory and composited into `mirrors.$version.tar.gz` and `default_configs.$version.tar.gz`*

Before a merge is completed you will be prompted with the merge strategy.

```
╒═════════════╤════════════════╤═════════════════════════════════════════════════════════════════════════════════════════╕
│ File Type   │ Merge Action   │ Path                                                                                    │
╞═════════════╪════════════════╪═════════════════════════════════════════════════════════════════════════════════════════╡
│ file        │ overwrite      │ default_configs/logstash/pipelines.yml                                                  │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ directory   │ create         │ default_configs/logstash/entity_snapshots                                               │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ directory   │ create         │ default_configs/logstash/entity_snapshots/conf.d                                        │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ file        │ write          │ default_configs/logstash/entity_snapshots/conf.d/20_filter_10_normalize.conf.disabled   │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ file        │ write          │ default_configs/logstash/entity_snapshots/conf.d/30_output_elastic.conf                 │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ file        │ write          │ default_configs/logstash/entity_snapshots/conf.d/10_input_entity_snapshot_pipeline.conf │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ directory   │ create         │ default_configs/logstash/entity_snapshots/templates                                     │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ file        │ write          │ default_configs/logstash/entity_snapshots/templates/entity_snapshot.template.json       │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ file        │ overwrite      │ default_configs/logstash/suricata/conf.d/10_input_pipeline.conf                         │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ file        │ write          │ default_configs/logstash/suricata/conf.d/30_output_kafka.conf                           │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ file        │ write          │ default_configs/logstash/zeek/conf.d/30_output_10_kafka.conf                            │
├─────────────┼────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ file        │ overwrite      │ default_configs/logstash/zeek/conf.d/10_input_zeek_pipeline.conf                        │
╘═════════════╧════════════════╧═════════════════════════════════════════════════════════════════════════════════════════╛

Detected 12 changes when building merge strategy for base_config_set/ <- logstash_docker_kafka_config_set_delta/
OK with the above merge? [Y|n]: 
```

### Using your new Mirrors and Configs in DynamiteNSM

To update your mirrors/configs to point to your own S3 repository simply overwrite the 

`DEEFAULT_CONFIGS_URL` and `MIRRORS_CONFIG_URL` in your [const.py](https://github.com/DynamiteAI/dynamite-nsm/blob/master/dynamite_nsm/const.py#L8-L10)

pointing to your S3 repo.