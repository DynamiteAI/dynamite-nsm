from dynamite_nsm import exceptions


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
