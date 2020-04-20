from dynamite_nsm import exceptions


class InstallSuricataError(exceptions.InstallError):
    """
    Thrown when Suricata fails to install
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while installing Suricata: {}".format(message)
        super(InstallSuricataError, self).__init__(msg)


class AlreadyInstalledSuricataError(InstallSuricataError):
    """
    Thrown when suricata is already installed
    """

    def __init__(self):
        msg = "Suricata is already installed."
        super(AlreadyInstalledSuricataError, self).__init__(msg)


class CallSuricataProcessError(exceptions.CallProcessError):
    """
    Thrown when suricata process encounters an error state
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling suricata process: {}".format(message)
        super(CallSuricataProcessError, self).__init__(msg)


class ReadsSuricataConfigError(exceptions.ReadConfigError):
    """
    Thrown when an suricata.yaml config option fails to read
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when reading suricata.yaml configuration: {}".format(message)
        super(ReadsSuricataConfigError, self).__init__(msg)


class SuricataRuleNotFoundError(Exception):
    """
    Thrown when attempting to disable a non-existent rule
    """

    def __init__(self, rule):
        """
        :param message: A suricata rule
        """
        msg = "Suricata rule does not exist: {}".format(rule)
        super(SuricataRuleNotFoundError, self).__init__(msg)


class SuricataInterfaceNotFoundError(Exception):
    """
    Thrown when attempting to disable a non-existing interface
    """

    def __init__(self, interface):
        """
        :param interface: A network interface
        """
        msg = "Suricata interface does not exist: {}".format(interface)
        super(SuricataInterfaceNotFoundError, self).__init__(msg)


class UninstallSuricataError(exceptions.UninstallError):
    """
    Thrown when Suricata fails to uninstall
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while uninstalling Suricata: {}".format(message)
        super(UninstallSuricataError, self).__init__(msg)


class WriteSuricataConfigError(exceptions.WriteConfigError):
    """
    Thrown when an suricata.yaml config option fails to write
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing suricata.yaml configuration: {}".format(message)
        super(WriteSuricataConfigError, self).__init__(msg)