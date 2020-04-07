from dynamite_nsm import exceptions


class WriteSynesisConfigError(exceptions.WriteConfigError):
    """
    Thrown when an Synesis config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing Synesis environment variables: {}".format(message)
        super(WriteSynesisConfigError, self).__init__(msg)


class ReadSynesisConfigError(exceptions.ReadConfigError):
    """
    Thrown when an Synesis config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading Synesis environment variables: {}".format(message)
        super(ReadSynesisConfigError, self).__init__(msg)


class InstallSynesisError(exceptions.InstallError):
    """
    Thrown when Synesis fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing Synesis: {}".format(message)
        super(InstallSynesisError, self).__init__(msg)
