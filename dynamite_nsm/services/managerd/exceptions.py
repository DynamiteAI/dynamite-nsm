from dynamite_nsm import exceptions


class InstallManagerDaemonError(exceptions.InstallError):
    """
    Thrown when managerd fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing managerd: {}".format(message)
        super(InstallManagerDaemonError, self).__init__(msg)


class CallManagerDaemonProcessError(exceptions.CallProcessError):
    """
    Thrown when managerd process encounters an error state
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling managerd process: {}".format(message)
        super(CallManagerDaemonProcessError, self).__init__(msg)
