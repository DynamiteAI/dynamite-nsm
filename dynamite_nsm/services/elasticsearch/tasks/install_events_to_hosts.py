from typing import Optional

from dynamite_nsm import utilities
from dynamite_nsm.services.base import tasks


class EventsToHostsTask(tasks.BasePythonPackageInstallTask):
    def __init__(self, username: Optional[str] = 'admin', password: Optional[str] = 'admin',
                 target: Optional[str] = f'https://{utilities.get_primary_ip_address()}:9200'):
        super().__init__(name='install_events_to_hosts',
                         package_link='https://github.com/DynamiteAI/jobs/blob/master/events-to-hosts/dist/'
                                      'events_to_hosts-0.1.0-py3-none-any.whl?raw=true',
                         command='/usr/local/bin/events-to-hosts',
                         args=['--username', username, '--password', password, '--target', target],
                         description='a standalone commandline utility that will derive host information from Zeek and '
                                     'Suricata instances deployed on a dynamite-nsm stack.')


if __name__ == '__main__':
    from dynamite_nsm import utilities

    job = EventsToHostsTask(username='admin', password='admin',
                            target=f'https://{utilities.get_primary_ip_address()}:9200')
    job.download_and_install()
    job.create_cronjob(interval_minutes=5)
