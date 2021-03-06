from dynamite_nsm import exceptions


class InstallZeekError(exceptions.InstallError):
    """
    Thrown when Zeek fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing Zeek: {}".format(message)
        super(InstallZeekError, self).__init__(msg)


class AlreadyInstalledZeekError(InstallZeekError):
    """
    Thrown when zeek is already installed
    """

    def __init__(self):
        msg = "Zeek is already installed."
        super(AlreadyInstalledZeekError, self).__init__(msg)


class CallZeekProcessError(exceptions.CallProcessError):
    """
    Thrown when zeek process encounters an error state
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling zeek process: {}".format(message)
        super(CallZeekProcessError, self).__init__(msg)


class InvalidZeekStatusLogEntry(Exception):
    """
    Thrown when a Zeek stats.log entry is improperly formatted
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "Zeek status log entry is invalid: {}".format(message)
        super(InvalidZeekStatusLogEntry, self).__init__(msg)


class InvalidZeekBrokerLogEntry(Exception):
    """
    Thrown when a Zeek broker.log entry is improperly formatted
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "Zeek broker log entry is invalid: {}".format(message)
        super(InvalidZeekBrokerLogEntry, self).__init__(msg)


class InvalidZeekClusterLogEntry(Exception):
    """
    Thrown when a Zeek cluster.log entry is improperly formatted
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "Zeek cluster log entry is invalid: {}".format(message)
        super(InvalidZeekClusterLogEntry, self).__init__(msg)


class InvalidZeekReporterLogEntry(Exception):
    """
    Thrown when a Zeek reporter.log entry is improperly formatted
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "Zeek reporter log entry is invalid: {}".format(message)
        super(InvalidZeekReporterLogEntry, self).__init__(msg)
    
        
class ReadsZeekConfigError(exceptions.ReadConfigError):
    """
    Thrown when an Zeek config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading zeek.yaml configuration: {}".format(message)
        super(ReadsZeekConfigError, self).__init__(msg)


class ZeekLocalNetworkNotFoundError(Exception):
    """
    Thrown when attempting to remove a non-existent local network definition
    """

    def __init__(self, ip_and_cidr):
        """
        :param ip_and_cidr: The IP and CIDR of the attempted removal
        """
        msg = "Zeek local network does not exist: {}".format(ip_and_cidr)
        super(ZeekLocalNetworkNotFoundError, self).__init__(msg)


class ZeekScriptNotFoundError(Exception):
    """
    Thrown when attempting to disable a non-existent script
    """

    def __init__(self, rule):
        """
        :param rule: A zeek script
        """
        msg = "Zeek script does not exist: {}".format(rule)
        super(ZeekScriptNotFoundError, self).__init__(msg)


class ZeekLoggerNotFoundError(Exception):
    """
    Thrown when attempting to disable a non-existing logger
    """

    def __init__(self, logger_name):
        """
        :param logger_name: The name of the Zeek logger
        """
        msg = "Zeek logger does not exist: {}".format(logger_name)
        super(ZeekLoggerNotFoundError, self).__init__(msg)


class ZeekManagerNotFoundError(Exception):
    """
    Thrown when attempting to disable a non-existing logger
    """

    def __init__(self, manager_name):
        """
        :param manager_name: The name of the zeek manager
        """
        msg = "Zeek manager does not exist: {}".format(manager_name)
        super(ZeekManagerNotFoundError, self).__init__(msg)


class ZeekProxyNotFoundError(Exception):
    """
    Thrown when attempting to disable a non-existing proxy
    """

    def __init__(self, proxy_name):
        """
        :param proxy_name: The name of the zeek proxy
        """
        msg = "Zeek proxy does not exist: {}".format(proxy_name)
        super(ZeekProxyNotFoundError, self).__init__(msg)


class UninstallZeekError(exceptions.UninstallError):
    """
    Thrown when Zeek fails to uninstall
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while uninstalling Zeek: {}".format(message)
        super(UninstallZeekError, self).__init__(msg)


class ZeekWorkerNotFoundError(Exception):
    """
    Thrown when attempting to disable a non-existing worker
    """

    def __init__(self, worker_name):
        """
        :param worker_name: The name of the zeek worker
        """
        msg = "Zeek interface does not exist: {}".format(worker_name)
        super(ZeekWorkerNotFoundError, self).__init__(msg)


class WriteZeekConfigError(exceptions.WriteConfigError):
    """
    Thrown when an sites.local config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing zeek.yaml configuration: {}".format(message)
        super(WriteZeekConfigError, self).__init__(msg)
