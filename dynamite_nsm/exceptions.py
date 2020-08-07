class ArchiveExtractionError(Exception):
    """
    Thrown when a archive fails extract
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while attempting to extract archive: {}".format(message)
        super(ArchiveExtractionError, self).__init__(msg)


class CallProcessError(Exception):
    """
    Thrown when a process encounters an error state
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling process: {}".format(message)
        super(CallProcessError, self).__init__(msg)


class DownloadError(Exception):
    """
    Thrown when a file fails download
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while attempting to download file: {}".format(message)
        super(DownloadError, self).__init__(msg)


class InstallError(Exception):
    """
    Thrown when a component fails to install
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while attempting to install component: {}".format(message)
        super(InstallError, self).__init__(msg)


class InvalidOsPackageManagerDetectedError(Exception):
    def __init__(self):
        msg = "Did not detect a valid OS package manager; currently APT-GET & YUM are supported."
        super(InvalidOsPackageManagerDetectedError, self).__init__(msg)


class OsPackageManagerInstallError(Exception):

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while attempting to install an OS package: {}".format(message)
        super(OsPackageManagerInstallError, self).__init__(msg)


class OsPackageManagerRefreshError(Exception):

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while attempting to refresh packages: {}".format(message)
        super(OsPackageManagerRefreshError, self).__init__(msg)


class ReadConfigError(Exception):
    """
    Thrown when an config option fails to read
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing configuration: {}".format(message)
        super(ReadConfigError, self).__init__(msg)


class ReadJavaConfigError(ReadConfigError):
    """
    Thrown when a jvm.options option fails to read
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing jvm.options configuration: {}".format(message)
        super(ReadConfigError, self).__init__(msg)


class ResetPasswordError(Exception):
    """
    Thrown when a password fails to reset
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while attempting to reset password: {}".format(message)
        super(ResetPasswordError, self).__init__(msg)


class UninstallError(Exception):
    """
    Thrown when a component fails to uninstall
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while attempting to uninstall component: {}".format(message)
        super(UninstallError, self).__init__(msg)


class WriteConfigError(Exception):
    """
    Thrown when an config option fails to write
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing configuration: {}".format(message)
        super(WriteConfigError, self).__init__(msg)


class WriteJavaConfigError(WriteConfigError):
    """
    Thrown when an config jvm.options option fails to write
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred when writing jvm.options configuration: {}".format(message)
        super(WriteJavaConfigError, self).__init__(msg)
