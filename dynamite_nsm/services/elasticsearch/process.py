from typing import Optional

from dynamite_nsm import exceptions
from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm.services.elasticsearch import profile as elasticsearch_profile


class CallElasticProcessError(exceptions.CallProcessError):
    def __init__(self, message):
        """Thrown when elasticsearch process encounters an error state
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred while calling elasticsearch process: {}".format(message)
        super(CallElasticProcessError, self).__init__(msg)


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Elasticsearch Process
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If enabled, status will be printed in a tabulated style
        Returns:
            None
        """

        environ = utilities.get_environment_file_dict()
        process.BaseProcessManager.__init__(self, 'elasticsearch.service', 'elasticsearch.process',
                                            log_path=environ.get('ES_LOGS'),
                                            create_pid_file=False,
                                            stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)

        if not elasticsearch_profile.ProcessProfiler().is_installed():
            self.logger.error("Elasticsearch is not installed. Install it with 'dynamite elasticsearch install -h'")
            raise CallElasticProcessError("Elasticsearch is not installed.")