from dynamite_nsm import exceptions


class WriteLogstashConfigError(exceptions.WriteConfigError):
    """
    Thrown when an Logstash.yml config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing logstash.yml configuration: {}".format(message)
        super(WriteLogstashConfigError, self).__init__(msg)


class ReadLogstashConfigError(exceptions.ReadConfigError):
    """
    Thrown when an logstash.yml config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading logstash.yml configuration: {}".format(message)
        super(ReadLogstashConfigError, self).__init__(msg)


class InstallLogstashError(exceptions.InstallError):
    """
    Thrown when Logstash fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing logstash: {}".format(message)
        super(InstallLogstashError, self).__init__(msg)


class UninstallLogstashError(exceptions.UninstallError):
    """
    Thrown when Logstash fails to uninstall
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while uninstalling logstash: {}".format(message)
        super(UninstallLogstashError, self).__init__(msg)