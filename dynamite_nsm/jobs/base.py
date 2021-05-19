import sys
import subprocess
import crontab
from typing import List


class JobBase:

    def __init__(self, name: str, package_link: str, interval_minutes: int, command: str, args: List[str],
                 description: str):
        self.name = name
        self.package_link = package_link
        self.command = command
        self.args = args
        self.description = description
        self.interval_minutes = interval_minutes

    def download_and_install(self):
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', self.package_link])
            return True
        except subprocess.CalledProcessError:
            return False

    def create_cronjob(self):
        cron = crontab.CronTab(user='root')
        job = cron.new(
            command=f'{self.command} {" ".join(self.args)}'
        )
        job.minute.every(self.interval_minutes)
        cron.write()
