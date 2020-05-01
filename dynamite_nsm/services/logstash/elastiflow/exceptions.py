from dynamite_nsm import exceptions


class WriteElastiflowConfigError(exceptions.WriteConfigError):
    """
    Thrown when an Elastiflow config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing Elastiflow environment variables: {}".format(message)
        super(WriteElastiflowConfigError, self).__init__(msg)


class ReadElastiflowConfigError(exceptions.ReadConfigError):
    """
    Thrown when an Elastiflow config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading Elastiflow environment variables: {}".format(message)
        super(ReadElastiflowConfigError, self).__init__(msg)


class InstallElastiflowError(exceptions.InstallError):
    """
    Thrown when Elastiflow fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing Elastiflow: {}".format(message)
        super(InstallElastiflowError, self).__init__(msg)
