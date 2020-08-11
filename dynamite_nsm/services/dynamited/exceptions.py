from dynamite_nsm import exceptions


class CallDynamiteDaemonProcessError(exceptions.CallProcessError):
    """
    Thrown when dynamited process encounters an error state
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling dynamited process: {}".format(message)
        super(CallDynamiteDaemonProcessError, self).__init__(msg)


class InstallDynamiteDaemonError(exceptions.InstallError):
    """
    Thrown when dynamited fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing dynamited: {}".format(message)
        super(InstallDynamiteDaemonError, self).__init__(msg)


class AlreadyInstalledDynamiteDaemonError(InstallDynamiteDaemonError):
    """
    Thrown when dynamited is already installed
    """

    def __init__(self):
        msg = "Managerd is already installed."
        super(AlreadyInstalledDynamiteDaemonError, self).__init__(msg)


class UninstallDynamiteDaemonError(exceptions.UninstallError):
    """
    Thrown when dynamited fails to uninstall
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while uninstalling dynamited: {}".format(message)
        super(UninstallDynamiteDaemonError, self).__init__(msg)
