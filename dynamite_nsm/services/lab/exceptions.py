from dynamite_nsm import exceptions


class WriteLabConfigError(exceptions.WriteConfigError):
    """
    Thrown when DynamiteSDK/JupyterHub config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing DynamiteSDK/JupyterHub configurations: {}".format(message)
        super(WriteLabConfigError, self).__init__(msg)


class ReadLabConfigError(exceptions.ReadConfigError):
    """
    Thrown when a DynamiteSDK/JupyterHub config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading DynamiteSDK/JupyterHub configurations: {}".format(message)
        super(ReadLabConfigError, self).__init__(msg)


class InstallLabError(exceptions.InstallError):
    """
    Thrown when Lab fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing Lab: {}".format(message)
        super(InstallLabError, self).__init__(msg)


class UninstallLabError(exceptions.UninstallError):
    """
    Thrown when Lab fails to uninstall
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while uninstalling Lab: {}".format(message)
        super(UninstallLabError, self).__init__(msg)
