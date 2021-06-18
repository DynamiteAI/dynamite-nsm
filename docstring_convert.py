text = '''
        """
        Write out an updated configuration file, and optionally backup the old one.

        :param out_file_path: The path to the output file; if none given overwrites existing
        :param backup_directory: The path to the backup directory        
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