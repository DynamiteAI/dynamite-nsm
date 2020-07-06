from dynamite_nsm import exceptions


class InstallOinkmasterError(exceptions.InstallError):
    """
    Thrown when Oinkmaster fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing Oinkmaster: {}".format(message)
        super(InstallOinkmasterError, self).__init__(msg)


class UpdateSuricataRulesError(Exception):
    """
    Thrown when Suricata rules fail to update
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while updating Suricata rule-sets: {}".format(message)
        super(UpdateSuricataRulesError, self).__init__(msg)