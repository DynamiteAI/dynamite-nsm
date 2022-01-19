from typing import Optional
from dynamite_nsm.services.suricata.oinkmaster import update_suricata_rules
from dynamite_nsm.services.base.install import BaseInstallManager


class RuleUpdateManager(BaseInstallManager):

    def __init__(self, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """Update Suricata Rule-sets
        Args:
            stdout: Print the output to console
            verbose: Include detailed debug messages
        Returns:
            None
        """
        super().__init__('suricata.update', stdout=stdout, verbose=verbose, requires_root=False)

    def update(self):
        """Start the update process
        Returns:
            None
        """
        update_suricata_rules(stdout=self.stdout, verbose=self.verbose)
