# Commandline Installation

Install using **Python PIP** tool. Note that root access is required, as this command requires the ability to make system changes. 
Be sure to install this module as the `root` user.

```
[root@sensor]$ pip install dynamite-nsm
```

Once installed, confirm that it is in your $PATH
```
[root@sensor]$ which dynamite
/usr/local/bin/dynamite
```

If no value is returned above, create a symbolic link in your `/usr/bin/` directory.

```
[root@sensor]$ ln -s /usr/local/bin/dynamite /usr/bin/dynamite
```

Confirm that the installation was successful with `dynamite --version`
```
[root@sensor]# dynamite --version


                  ,,,,,                  ,▄▄▄▄╓
              .▄▓▀▀▀░▀▀▀▓▓╓            ╔▓▓▓▓▓▓▓▀▓
             #∩╓ ▀▓▓▓▓▓▓▓▄▀▓▄         ║▌▓▓▓▓▓▓▓▓╩▓
                ▀▓"▓▓▓▓▓▓▓▓∩▓▄ ,,▄▄▄▓▓▓▌▓▓▓▓▓▓▓▓╦▓
                 ▐▓╙▓▓▓▓▓▓▓▓▐▓▀▀▀^╙└"^^▀▓▀▓▓▓▓▀▒▓`
                 ▐▓]▓▓▓▓▓▓▓▓▐▓           ▀▀▀▀▀▀^
                ▄▓.▓▓▓▓▓▓▓▓Ü▓▀ ╙╙▀█▒▄▄,,
            '#ε╙╙▄▓▓▓▓▓▓▓▀▄▓▌        `╙▀▀▓▓▓▓▄▄╓,        ,,
              "█▓▄▄▓▓▓░▄▓▓▀  ╙╗,            '"▀▀█▓▓▓▓▓▄#╣▓▓▓▓
                 ║▀"▀▀└,       ▀▓▄                 ^▀▀▀▌▓▓▓▓▓╛
                ╔▓      ▓        ▀▓▄,╓╓,                ╙▀▀▀"
               ]▓▌      ╙▌        '▓▓▓▓▓▓⌐
            ╓▄▄▓▓░       ▓▌        ╫▓▓▓▓▓>
         ╓▓▀▓▓▓▓▓▀▓      ╙▓▌        ╙╙▀╙
        ╔▓▒▓▓▓▓▓▓▓░▓      ║▓╕
        ╚▌║▓▓▓▓▓▓▓╩▓       ▓▓
         ▀▓▀▓▓▓▓▀╠▓┘       ╚▓▓
           ▀▀██▀▀╙          ▓▓▓╓
                           ╫▓▓▓▓▓ε

            http://dynamite.ai

            Version: 0.7.0
```

## Troubleshooting

### Getting a `bash: dynamite: command not found` error.

This occurs when dynamite is not in your path. By default, `setup.py` will install dynamite to `/usr/local/bin/dynamite`.
Depending on your distribution this location may or may not be in your `$PATH`.

1. `sudo -i` 
2. `cd /usr/bin/`
3. `ln -s /usr/local/bin/dynamite .`
 
 
### Getting a `/bin/dynamite: /bin/python: bad interpreter: No such file or directory` error.

This occurs when `python` is upgraded, and the binary name changes, or `python` was uninstalled.

1. `sudo -i`
2. `whereis python` to confirm python was installed. If it is uninstalled, simply install `python`.
3. `nano /usr/local/bin/dynamite` and replace `#! /usr/bin/python` with the name of the new `python` binary.