from typing import Optional
from dynamite_nsm.services.suricata.oinkmaster import update_suricata_rules
from dynamite_nsm.services.base.install import BaseInstallManager


class RuleUpdateManager(BaseInstallManager):

    def __init__(self, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """
        super().__init__('suricata.update', stdout=stdout, verbose=verbose)

    def update(self):
        update_suricata_rules(stdout=self.stdout, verbose=self.verbose)