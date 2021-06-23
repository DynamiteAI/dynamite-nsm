import json
import requests
from time import sleep
from typing import Dict, Optional, Tuple

from dynamite_nsm import utilities
from dynamite_nsm.services.base import tasks
from dynamite_nsm.services.elasticsearch import process
from dynamite_nsm.services.elasticsearch import profile


class UpdateClusterSettings(tasks.BaseTask):

    def __init__(self, network_host: Optional[str] = utilities.get_primary_ip_address(),
                 http_port: Optional[int] = 9200,
                 max_attempts: Optional[int] = 10,
                 terminate_elasticsearch: Optional[bool] = True):
        self.network_host = network_host
        self.http_port = http_port
        self.max_attempts = max_attempts
        self.terminate_elasticsearch = terminate_elasticsearch
        super(UpdateClusterSettings, self).__init__(name='configure_cluster',
                                                    package_link='N/A',
                                                    description='Configure the cluster')

    def invoke(self) -> Tuple[int, Dict]:
        es_url = f'https://{self.network_host}:{self.http_port}'
        es_cluster_data = {'persistent': {'script.max_compilations_rate': '1000/5m'},
                           'transient': {'script.max_compilations_rate': '1000/5m'}}
        attempts = 0
        es_process_profile = profile.ProcessProfiler()
        if not es_process_profile.is_listening():
            process.ProcessManager().start()
        while not es_process_profile.is_listening() and attempts < self.max_attempts:
            attempts += 1
            sleep(10)
        r = requests.put(
            url=f'{es_url}/_cluster/settings',
            data=json.dumps(es_cluster_data),
            auth=('admin', 'admin'),
            headers={'content-type': 'application/json'},
            verify=False
        )
        if self.terminate_elasticsearch:
            process.ProcessManager().stop()
        if r.status_code != 200:
            return r.status_code, {'error': r.text}
        else:
            return r.status_code, r.json()
