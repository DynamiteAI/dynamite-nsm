text = '''
    """
    Add an interface to an existing parser.

    :param parent_parser: The parent parser to add the interface too
    :param interface_name: The name of this interface as it will appear in the commandline utility
    :param interface: The interface object itself
    :param interface_group_name: A name identifying where in the component, interface, sub-interface hierarchy this service_interface should be placed
    :return: The parser object
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