import sys
import requests
import subprocess
from time import sleep

import crontab
from dynamite_nsm import const
from dynamite_nsm import utilities
from typing import List, Optional, Tuple


class BaseTask:
    def __init__(self, name: str, package_link: Optional[str] = None, description: Optional[str] = None):
        self.name = name
        self.package_link = package_link
        self.description = description

    def download_and_install(self):
        raise NotImplemented()

    def invoke(self):
        raise NotImplemented()


class BaseShellCommandTask(BaseTask):

    def __init__(self, name: str, package_link: str, command: str, args: List[str], description: Optional[str] = None):
        super().__init__(name, package_link, description)
        self.command = command
        self.args = args

    def invoke(self, shell=False) -> Tuple[bytes, bytes]:
        p = subprocess.Popen(executable=self.command, args=self.args, shell=shell, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        return out, err

    def create_cronjob(self, interval_minutes: int):
        cron = crontab.CronTab(user='root')
        job = cron.new(
            command=f'{self.command} {" ".join(self.args)}',
            comment=self.name
        )
        job.minute.every(interval_minutes)
        cron.write()

    def remove_cronjob(self):
        cron = crontab.CronTab(user='root')
        cron.remove_all(comment=self.name)


class BasePythonPackageInstallTask(BaseShellCommandTask):

    def __init__(self, name: str, package_link: str, command: str, args: List[str], description: Optional[str]):
        super().__init__(name, package_link, command, args, description)

    def download_and_install(self) -> bool:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', self.package_link])
            return True
        except subprocess.CalledProcessError:
            return False


class BaseKibanaPackageInstallTask(BaseTask):

    def __init__(self, name: str, kibana_package_link: Optional[str] = None, username: Optional[str] = 'admin',
                 password: Optional[str] = 'admin',
                 target: Optional[str] = f'http://{utilities.get_primary_ip_address()}:5601',
                 tenant: Optional[str] = '',
                 description: Optional[str] = ''):
        super().__init__(name, kibana_package_link, description)
        self.username = username
        self.password = password
        self.target = target
        self.tenant = tenant

    def kibana_api_up(self):
        """
        Check if Kibana API is accessible
        """
        try:
            r = requests.get(
                url=f'{self.target}/api',
                auth=(self.username, self.password),
                headers={'kbn-xsrf': 'true'},
                verify=False
            )
        except requests.ConnectionError:
            return False
        return r.status_code == 404

    def download_and_install(self) -> bool:
        from dynamite_nsm.services.kibana.process import ProcessManager
        from dynamite_nsm.services.kibana.package import SavedObjectsManager
        kibana_process = ProcessManager(stdout=True)
        kibana_process.start()
        manager = SavedObjectsManager(username=self.username, password=self.password, target=self.target, stdout=True)
        download_path = f'{const.INSTALL_CACHE}/{self.name}.tar.gz'
        utilities.download_file(self.package_link, download_path)
        attempts = 0
        while not self.kibana_api_up() and attempts < 5:
            attempts += 1
            sleep(10)
        res = manager.install(download_path, ignore_warnings=True, tenant=self.tenant)
        kibana_process.stop()
        return res
