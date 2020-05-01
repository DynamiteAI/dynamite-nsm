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