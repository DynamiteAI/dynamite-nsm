text = '''
        """
        Algorithm for determining the assignment of CPUs for Zeek workers

        :param interface_names: A list of network interface names
        :param strategy: 'aggressive', results in more CPUs pinned per interface, sometimes overshoots resources; 'conservative', results in less CPUs pinned per interface, but never overshoots resources
        :param cpus: If None, we'll derive this by looking at the cpu core count, otherwise a list of cpu cores (E.G [0, 1, 2])
        :return: A dictionary containing Zeek worker configuration
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