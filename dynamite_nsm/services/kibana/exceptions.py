from dynamite_nsm import exceptions


class CallKibanaProcessError(exceptions.CallProcessError):
    """
    Thrown when kibana process encounters an error state
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling kibana process: {}".format(message)
        super(CallKibanaProcessError, self).__init__(msg)


class CreateKibanaObjectsError(Exception):
    """
    Thrown kibana objects fail to be created
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while creating Kibana dashboards, visualizations, and saved-searches: {}".format(
            message)
        super(CreateKibanaObjectsError, self).__init__(msg)


class InstallKibanaError(exceptions.InstallError):
    """
    Thrown when Kibana fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing Kibana: {}".format(message)
        super(InstallKibanaError, self).__init__(msg)


class AlreadyInstalledKibanaError(InstallKibanaError):
    """
    Thrown when kibana is already installed
    """

    def __init__(self):
        msg = "Kibana is already installed."
        super(AlreadyInstalledKibanaError, self).__init__(msg)


class ReadKibanaConfigError(exceptions.ReadConfigError):
    """
    Thrown when an kibana.yml config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading kibana.yml configuration: {}".format(message)
        super(ReadKibanaConfigError, self).__init__(msg)


class UninstallKibanaError(exceptions.UninstallError):
    """
    Thrown when Kibana fails to uninstall
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while uninstalling Kibana: {}".format(message)
        super(UninstallKibanaError, self).__init__(msg)


class WriteKibanaConfigError(exceptions.WriteConfigError):
    """
    Thrown when an kibana.yml config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing kibana.yml configuration: {}".format(message)
        super(WriteKibanaConfigError, self).__init__(msg)