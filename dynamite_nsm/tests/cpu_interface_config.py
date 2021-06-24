import json
from dynamite_nsm import utilities

CPUS = [0, 1, 2, 3, 4, 5, 6, 7, 8]
NET_INTS = ['mon0', 'mon1', 'mon2']
print(json.dumps(utilities.get_optimal_cpu_interface_config(NET_INTS, CPUS, custom_ratio=3), indent=2))