class ArchiveExtractionError(Exception):
    def __init__(self, message):
        """Thrown when an archive fails to extract
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred while attempting to extract archive: {}".format(message)
        super(ArchiveExtractionError, self).__init__(msg)


class CallProcessError(Exception):
    def __init__(self, message):
        """Thrown when an external process encounters an error state
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred while calling process: {}".format(message)
        super(CallProcessError, self).__init__(msg)


class DownloadError(Exception):
    def __init__(self, message):
        """Thrown when a file fails download
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred while attempting to download file: {}".format(message)
        super(DownloadError, self).__init__(msg)


class DynamiteNotSetupError(Exception):
    def __init__(self):
        msg = "You must run dynamite setup install before you can continue."
        super(DynamiteNotSetupError, self).__init__(msg)


class InstallError(Exception):
    def __init__(self, message):
        """Thrown when a component fails to install
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred while attempting to install component: {}".format(message)
        super(InstallError, self).__init__(msg)


class MethodNotImplementedError(Exception):
    def __init__(self):
        msg = "This method is currently not implemented by this component."
        super(MethodNotImplementedError, self).__init__(msg)


class ReadConfigError(Exception):

    def __init__(self, message):
        """Thrown when we couldn't find a config file at that location or permissions issues
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred when reading configuration: {}".format(message)
        super(ReadConfigError, self).__init__(msg)


class ReadJavaConfigError(ReadConfigError):
    def __init__(self, message):
        """Thrown when jvm.options file fails to read
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred when writing jvm.options configuration: {}".format(message)
        super(ReadConfigError, self).__init__(msg)


class ResetPasswordError(Exception):
    def __init__(self, message):
        """Thrown when a password failed to reset
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred while attempting to reset password: {}".format(message)
        super(ResetPasswordError, self).__init__(msg)


class RequiresRootError(PermissionError):
    def __init__(self):
        msg = "This operation must be run with root."
        super(RequiresRootError, self).__init__(msg)


class UninstallError(Exception):
    """Thrown when a component fails to uninstall fully
    Args:
        message: A more specific error message
    Returns:
        None
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while attempting to uninstall component: {}".format(message)
        super(UninstallError, self).__init__(msg)


class WriteConfigError(Exception):
    def __init__(self, message):
        """Thrown when a config file does not write out properly
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred when writing configuration: {}".format(message)
        super(WriteConfigError, self).__init__(msg)


class WriteJavaConfigError(WriteConfigError):

    def __init__(self, message):
        """Thrown when the jvm.options file fails to write
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred when writing jvm.options configuration: {}".format(message)
        super(WriteJavaConfigError, self).__init__(msg)
