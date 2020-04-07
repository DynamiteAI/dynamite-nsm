from dynamite_nsm import exceptions


class InstallPfringError(exceptions.InstallError):
    """
    Thrown when Pfring fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing PF_RING: {}".format(message)
        super(InstallPfringError, self).__init__(msg)