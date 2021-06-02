## Install DynamiteNSM
DynamiteNSM is 100% implemented in Python3, and can thus be installed directly via pip.

```bash
pip install dynamite-nsm
```

Alternatively, developers may also wish to build from source.

```bash
git clone https://github.com/DynamiteAI/dynamite-nsm.git && 
pip install dynamite-nsm/
```

> ⓘ If you opt, for this method, and are curious about contributing to this project be sure to check out our 
developer guides!

Once installed, you should be able to call `dynamite` directly from the commandline. 
Keep in mind that `dynamite` requires `root` access in order to run basically any command.

Download any default configuration or mirror updates.
```bash
sudo dynamite updates install
```

## Troubleshooting

### Command not found

**Symptoms**: You run any `dynamite` command, but the shell reports that the `dynamite` Could not be found or something similar.

| Problem                       | Description                                                                                                   | Solution                                                                                                                                                                                                                       |
|-------------------------------|---------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `dynamite` not in $PATH       | Occurs when `/usr/local/bin` is not in the $PATH.                                                             | Simply create a symlink `ln -s /usr/local/bin/dynamite /usr/bin/dynamite` and then re-run the command.                                                                                                                         |
| `pip install dynamite` failed | `pip install` can partially succeed then fail on a single dependency preventing the installation to continue. | Re-run the `pip install` command again, note any errors. Often these can be corrected by installing pre-requisite OS libraries. A few common libraries that when missing can cause issues: (`gcc`, `g++`, `make`, `python3-pip`) |
