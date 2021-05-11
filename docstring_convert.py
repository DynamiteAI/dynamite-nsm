text = '''
        """ 
        Install Logstash
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/logstash/)
        :param download_logstash_archive: If True, download the Logstash archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
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