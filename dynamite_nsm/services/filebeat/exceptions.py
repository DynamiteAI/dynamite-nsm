from dynamite_nsm import exceptions


class InvalidAgentTag(Exception):
    """
    Thrown when Filebeat agent tag is invalid
    """

    def __init__(self):
        msg = "Agent tag must be between 5 and 30 characters, and contain alphanumeric and '_' characters only."
        super(InvalidAgentTag, self).__init__(msg)


class InstallFilebeatError(exceptions.InstallError):
    """
    Thrown when Filebeat fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing Filebeat: {}".format(message)
        super(InstallFilebeatError, self).__init__(msg)


class InvalidFilebeatStatusLogEntry(Exception):
    """
    Thrown when a Filebeat log entry is improperly formatted
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "FileBeat log entry is invalid: {}".format(message)
        super(InvalidFilebeatStatusLogEntry, self).__init__(msg)


class AlreadyInstalledFilebeatError(InstallFilebeatError):
    """
    Thrown when filebeat is already installed
    """

    def __init__(self):
        msg = "Filebeat is already installed."
        super(AlreadyInstalledFilebeatError, self).__init__(msg)
        
        
class CallFilebeatProcessError(exceptions.CallProcessError):
    """
    Thrown when filebeat process encounters an error state
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling filebeat process: {}".format(message)
        super(CallFilebeatProcessError, self).__init__(msg)
        

class UninstallFilebeatError(exceptions.UninstallError):
    """
    Thrown when elasticsearch fails to uninstall
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while uninstalling filebeat: {}".format(message)
        super(UninstallFilebeatError, self).__init__(msg)
        

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


class ReadFilebeatModuleError(exceptions.ReadConfigError):
    """
    Thrown when an modules.d/*.yml config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading a Filebeat module configuration: {}".format(message)
        super(ReadFilebeatModuleError, self).__init__(msg)


class WriteFilebeatConfigError(exceptions.WriteConfigError):
    """
    Thrown when an Filebeat.yml config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing filebeat.yml configuration: {}".format(message)
        super(WriteFilebeatConfigError, self).__init__(msg)


class WriteFilebeatModuleError(exceptions.WriteConfigError):
    """
    Thrown when an modules.d/*.yml config fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing Filebeat module configuration: {}".format(message)
        super(WriteFilebeatModuleError, self).__init__(msg)