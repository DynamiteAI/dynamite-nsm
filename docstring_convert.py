text = '''
    """
    Given a callable function returns a three part definition for that function

    :param func: A callable function
    :return: A tuple with the (function.__name__, function.__annotations__, inspect.getdoc(function))
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