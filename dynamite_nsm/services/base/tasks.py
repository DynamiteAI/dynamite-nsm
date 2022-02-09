import os
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


class BaseShellCommandsTask(BaseTask):

    def __init__(self, name: str, package_link: str, commands: List[List[str]], description: Optional[str] = None):
        super().__init__(name, package_link, description)
        self.commands = commands

    def invoke(self, shell: Optional[bool] = False, cwd: Optional[str] = os.getcwd()) -> List[Tuple[List, bytes, bytes]]:
        results = []
        for command in self.commands:
            if not shell:
                _bin, args = command[0], command[1:]
                p = subprocess.Popen(executable=_bin, args=args, shell=shell, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, cwd=cwd, env=utilities.get_environment_file_dict())
            else:

                p = subprocess.Popen(' '.join(command), shell=shell, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, cwd=cwd, env=utilities.get_environment_file_dict())
            out, err = p.communicate()
            results.append((command, out, err))
        return results

    def create_cronjob(self, interval_minutes: int):
        cron = crontab.CronTab(user='root')
        command_string = ''
        for command in self.commands:
            command_string += f'{" ".join(command)};'
        job = cron.new(
            command=command_string,
            comment=self.name
        )
        job.minute.every(interval_minutes)
        cron.write()

    def remove_cronjob(self):
        cron = crontab.CronTab(user='root')
        cron.remove_all(comment=self.name)


class BaseShellCommandTask(BaseShellCommandsTask):

    def __init__(self, name: str, package_link: str, command: str, args: List[str], description: Optional[str] = None):
        command = [
            command
        ]
        command.extend(args)

        super().__init__(name, commands=[command], package_link=package_link, description=description)
        self.command = command
        self.args = args


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
