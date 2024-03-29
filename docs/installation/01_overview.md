# Installation Overview

> ⚠️ We will need to make changes to your system in order to function properly. 
> We highly recommend installing the `dynamite-nsm` package on a fresh installation of [Linux](../../requirements/01_supported_operating_systems).

---

> ⚠️ `root` access is needed as `dynamite` will need to be able to install and uninstall services.


`dynamite-nsm` is a [Python3.7+](https://www.python.org/downloads/) compatible package that can be installed directly through [pip](https://pip.pypa.io/en/stable/installing/).


```bash
sudo pip install dynamite-nsm
```


Alternatively, developers may also wish to build from source.

```bash
git clone https://github.com/DynamiteAI/dynamite-nsm.git && 
sudo pip install dynamite-nsm/
```

> ⓘ If you opt, for this method, and are curious about contributing to this project be sure to check out our 
[developer guides](../../guides/developers/01_overview)!

Once installed, you should be able to call `dynamite` directly from the commandline. 
We will use the `dynamite` commandline utility for setting up and managing all the services we install.
Keep in mind that the `dynamite` utility requires `root` access in order to run `install` and `uninstall` commands.

Before you can begin installing services you must initialize the system with the `setup` bootstrapper as root.
```bash
sudo dynamite setup install
```

This command will download configuration updates, setup directory structure, and add a `sudoers.d/` policy 
allowing users in the `dynamite` group to run some elevated commands.

## Troubleshooting

### Command not found

**Symptoms**: You run any `dynamite` command, but the shell reports that the `dynamite` Could not be found or something similar.

| Problem                       | Description                                                                                                   | Solution                                                                                                                                                                                                                       |
|-------------------------------|---------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `dynamite` not in $PATH       | Occurs when `/usr/local/bin` is not in the $PATH.                                                             | Simply create a symlink `ln -s /usr/local/bin/dynamite /usr/bin/dynamite` and then re-run the command.                                                                                                                         |
| `pip install dynamite` failed | `pip install` can partially succeed then fail on a single dependency preventing the installation to continue. | Re-run the `pip install` command again, note any errors. Often these can be corrected by installing pre-requisite OS libraries. A few common libraries that when missing can cause issues: (`gcc`, `g++`, `make`, `python3-pip`) |
