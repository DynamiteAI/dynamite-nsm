text = '''
    """
    """
    Given a rule_id (and optionally the R.O file-handle associated with the suricata_rule_definitions.json file
    Return the definition, categories, and friendly_name of a given script
    :param rule_id: A numeric identifier representing a Suricata rule.
    :param fh: File handle of the definitions file
    :return: A dictionary of the format {"friendly_name": <str>, "description": <str>, "categories": <list>}
    """
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