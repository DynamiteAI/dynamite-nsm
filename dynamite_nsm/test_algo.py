import json
import math
import itertools

# v *** MODIFY THESE PARAMETERS *** v #

CPU_GROUPING_STRATEGY = 'aggressive'  # aggressive/conservative
NETWORK_INTERFACES = ['mon0', 'mon1', 'mon2', 'mon3', 'mon4', 'mon5']
CPU_COUNT = 33
# ^ *** MODIFY THESE PARAMETERS *** ^ #


cpus = [c for c in range(0, CPU_COUNT)]

# Reserve 0 for KERNEL/Userland opts
available_cpus = cpus[1:]


def grouper(n, iterable):
    args = [iter(iterable)] * n
    return itertools.izip_longest(*args)


def create_workers(net_interfaces, available_cpus):
    idx = 0
    zeek_worker_configs = []
    for net_interface in net_interfaces:
        if idx >= len(available_cpus):
            idx = 0
        if isinstance(available_cpus[idx], int):
            available_cpus[idx] = [available_cpus[idx]]
        zeek_worker_configs.append(
            dict(
                name='dynamite-worker-' + net_interface,
                interface=net_interface,
                lb_procs=len(available_cpus[idx]),
                pinned_cpus=available_cpus[idx]
            )
        )
        idx += 1
    return zeek_worker_configs


if len(available_cpus) <= len(NETWORK_INTERFACES):
    # Wrap the number of CPUs around the number of network interfaces;
    # Since there are more network interfaces than CPUs; CPUs will be assigned more than once
    # lb_procs will always be 1

    zeek_workers = create_workers(NETWORK_INTERFACES, available_cpus)

else:
    # In this scenario we choose from one of two strategies
    #  1. Aggressive:
    #     - Take the ratio of network_interfaces to available CPUS; ** ROUND UP **.
    #     - Group the available CPUs by this integeger
    #       (if the ratio == 2 create as many groupings of 2 CPUs as possible)
    #     - Apply the same wrapping logic used above, but with the CPU groups instead of single CPU instances
    #  2. Conservative:
    #     - Take the ratio of network_interfaces to available CPUS; ** ROUND DOWN **.
    #     - Group the available CPUs by this integeger
    #       (if the ratio == 2 create as many groupings of 2 CPUs as possible)
    #     - Apply the same wrapping logic used above, but with the CPU groups instead of single CPU instances
    aggressive_ratio = int(math.ceil(len(available_cpus)/float(len(NETWORK_INTERFACES))))
    conservative_ratio = int(math.floor(len(available_cpus)/float(len(NETWORK_INTERFACES))))
    if CPU_GROUPING_STRATEGY == 'aggressive':
        cpu_groups = grouper(aggressive_ratio, available_cpus)
    else:
        cpu_groups = grouper(conservative_ratio, available_cpus)

    temp_cpu_groups = []
    for cpu_group in cpu_groups:
        cpu_group = [c for c in cpu_group if c]
        temp_cpu_groups.append(cpu_group)
    cpu_groups = temp_cpu_groups

    zeek_workers = create_workers(NETWORK_INTERFACES, cpu_groups)


print(json.dumps(zeek_workers, indent=1))