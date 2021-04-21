
from typing import Optional
from dynamite_nsm.services.base import install


class InstallManager(install.BaseInstallManager):

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False):
        super().__init__('node', verbose, stdout)
        self.stdout = stdout
        self.verbose = verbose

