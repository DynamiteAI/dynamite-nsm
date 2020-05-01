# Updating

DynamiteNSM manages releases through its GitHub [release page](https://github.com/DynamiteAI/dynamite-nsm/releases), and you can always find the latest stable release by installing via `pip`.

Our Pypi project is located [here](https://pypi.org/project/dynamite-nsm/).
```
pip3 install dynamite-nsm
```

## Updating Mirrors

We also maintain a separate set of default-configurations and mirrors. When a user runs an `install` action against a component, it first applies a set of default-configurations, and downloads relevant components from a set of mirrors.

Occasionally, we tweek these configurations to improve performance, or add a new feature.

To download the latest configuration run:

```
dynamite updates install
```

## Updating Suricata Rules

We leverage [Emerging Threat Signatures](https://rules.emergingthreats.net/) to identify the latest malicious attacks. To update your ruleset simply run:

```
dynamite agent update
``` 