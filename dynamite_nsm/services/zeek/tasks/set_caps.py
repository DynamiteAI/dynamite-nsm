import os
from typing import List, Optional, Tuple
from dynamite_nsm.services.base import tasks


class SetCapturePermissions(tasks.BaseShellCommandsTask):

    def __init__(self, zeek_install_directory: str):
        super().__init__(name='set_zeek_capture_permissions', package_link='N/A', commands=[
            ['/usr/sbin/setcap', 'cap_net_raw=eip', f'{zeek_install_directory}/bin/zeek'],
            ['/usr/sbin/setcap', 'cap_net_raw=eip', f'{zeek_install_directory}/bin/capstats'],
        ])

    def invoke(self, shell: Optional[bool] = False, cwd: Optional[str] = os.getcwd()) -> List[Tuple[List, bytes, bytes]]:
        return super().invoke(shell, cwd)
