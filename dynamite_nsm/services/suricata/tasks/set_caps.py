import os
from typing import List, Optional, Tuple
from dynamite_nsm.services.base import tasks


class SetCapturePermissions(tasks.BaseShellCommandsTask):

    def __init__(self, suricata_install_directory: str):
        super().__init__(name='set_zeek_capture_permissions', package_link='N/A', commands=[
            ['/usr/sbin/setcap', 'cap_net_raw,cap_net_admin=eip', f'{suricata_install_directory}/bin/suricata'],
        ])

    def invoke(self, shell: Optional[bool] = False, cwd: Optional[str] = os.getcwd()) -> List[Tuple[List, bytes, bytes]]:
        return super().invoke(shell, cwd)
