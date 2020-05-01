from dynamite_nsm import exceptions


class CallElasticProcessError(exceptions.CallProcessError):
    """
    Thrown when elasticsearch process encounters an error state
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling elasticsearch process: {}".format(message)
        super(CallElasticProcessError, self).__init__(msg)


class InstallElasticsearchError(exceptions.InstallError):
    """
    Thrown when elasticsearch fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing elasticsearch: {}".format(message)
        super(InstallElasticsearchError, self).__init__(msg)


class AlreadyInstalledElasticsearchError(InstallElasticsearchError):
    """
    Thrown when elasticsearch is already installed
    """

    def __init__(self):
        msg = "ElasticSearch is already installed."
        super(AlreadyInstalledElasticsearchError, self).__init__(msg)


class ReadElasticConfigError(exceptions.ReadConfigError):
    """
    Thrown when an Elasticsearch.yml config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading elasticsearch.yml configuration: {}".format(message)
        super(ReadElasticConfigError, self).__init__(msg)


class UninstallElasticsearchError(exceptions.UninstallError):
    """
    Thrown when elasticsearch fails to uninstall
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while uninstalling elasticsearch: {}".format(message)
        super(UninstallElasticsearchError, self).__init__(msg)


class WriteElasticConfigError(exceptions.WriteConfigError):
    """
    Thrown when an Elasticsearch.yml config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing elasticsearch.yml configuration: {}".format(message)
        super(WriteElasticConfigError, self).__init__(msg)

