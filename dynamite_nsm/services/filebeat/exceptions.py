from dynamite_nsm import exceptions


class WriteFilebeatConfigError(exceptions.WriteConfigError):
    """
    Thrown when an FIlebeat.yml config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing filebeat.yml configuration: {}".format(message)
        super(WriteFilebeatConfigError, self).__init__(msg)


class ReadFilebeatConfigError(exceptions.ReadConfigError):
    """
    Thrown when an FIlebeat.yml config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading filebeat.yml configuration: {}".format(message)
        super(ReadFilebeatConfigError, self).__init__(msg)

