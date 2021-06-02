text = '''
        """

        Redis endpoint configuration where events should be sent

        :param target_strings: A list of Redis hosts, and their service port (E.G ["192.168.0.9 6379"]
        :param index: The key format string to use. If this string contains field references, such as fields.name, the fields must exist, or the rule fails.
        :param load_balance: If included and multiple hosts or workers are configured, the output plugin load balances published events onto all Redis hosts. Otherwise, the output plugin sends all events to only one host (determined at random) and will switch to another host if the currently selected one becomes unreachable. The default value is true.
        :param socks_5_proxy_url: The full url to the SOCKS5 proxy used for encapsulating the beat protocol
        :param workers: The number of workers to use for each host configured to publish events to Redis. Use this setting along with the load_balance option. For example, if you have 2 hosts and 3 workers, in total 6 workers are started (3 for each host).
        :param max_batch_size: The maximum number of events to bulk in a single Redis request or pipeline. The default is 2048.
        :param password: The password to authenticate with. The default is no authentication.
        :param db: The Redis database number where the events are published. The default is 0.
        """
'''
params = []
return_val = 'None'
for line in text.split('\n'):
    line = line.strip()
    if line.strip() == '"""':
        continue
    elif not line.strip():
        continue
    elif line.startswith(':param'):
        param, desc = line.replace(':param', '').split(':')
        param = param.strip()
        desc = desc.strip()
        params.append((param, desc))
    elif ':returns' in line or ':return' in line:
        return_val = line.replace(':returns', '').replace(':return', '').replace(':', '')
    else:
        description = line.replace('"""', '').strip()



print('"""' +
description + '\n' +
'Args: \n' + '' +
           '\n'.join('    {}: {}'.format(param, desc) for param, desc in params) +
f'\nReturns: \n    {return_val}' +'\n"""'
)