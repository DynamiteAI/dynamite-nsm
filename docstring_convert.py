text = '''
        """
        A Zeek worker process

        :param worker_name: The name of the worker
        :param interface_name: The name of a network interface
        :param cluster_id: A unique integer associated with this worker maps to af_packet_fanout_id
        :param cluster_type: The algorithm used to spread traffic between sockets. cluster_flow (FANOUT_HASH), cluster_cpu (FANOUT_CPU), cluster_qm (FANOUT_QM). Maps to af_packet_fanout_mode
        :param load_balance_processes: The number of Zeek processes associated with a given worker
        :param pinned_cpus: Core affinity for the processes (iterable),
        :param host: The host on which the worker is running
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