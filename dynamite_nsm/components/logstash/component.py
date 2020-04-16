from dynamite_nsm.utilities import prompt_password
from dynamite_nsm.components.base import component
from dynamite_nsm.components.logstash import execution_strategy


class LogstashComponent(component.BaseComponent):
    """
    LogStash Component Wrapper intended for general use
    """

    def __init__(self, listen_address="0.0.0.0", elasticsearch_host="localhost", elasticsearch_port=9200,
                 elasticsearch_password='changeme', install_heap_size_gigs=4, install_jdk=True,
                 prompt_on_uninstall=True, check_elasticsearch_connection=True, stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="Logstash",
            component_description="Process, normalize, and send network events to a data-store.",
            install_strategy=execution_strategy.LogstashInstallStrategy(
                listen_address=listen_address,
                elasticsearch_host=elasticsearch_host,
                elasticsearch_port=elasticsearch_port,
                elasticsearch_password=elasticsearch_password,
                heap_size_gigs=install_heap_size_gigs,
                install_jdk=install_jdk,
                check_elasticsearch_connection=check_elasticsearch_connection,
                stdout=stdout,
                verbose=verbose
            ),
            uninstall_strategy=execution_strategy.LogstashUninstallStrategy(
                stdout=stdout,
                prompt_user=prompt_on_uninstall
            ),
            process_start_strategy=execution_strategy.LogstashProcessStartStrategy(
                stdout=stdout,
                status=True
            ),
            process_stop_strategy=execution_strategy.LogstashProcessStopStrategy(
                stdout=stdout,
                status=True
            ),
            process_restart_strategy=execution_strategy.LogstashProcessRestartStrategy(
                stdout=stdout,
                status=True
            ),
            process_status_strategy=execution_strategy.LogstashProcessStatusStrategy()
        )


class LogstashCommandlineComponent(component.BaseComponent):
    """
    LogStash Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="LogStash",
            component_description="Process, normalize, and send network events to a data-store.",
        )

        if args.action_name == "install":
            es_password = args.elastic_password
            if not es_password:
                es_password = prompt_password("Enter the password for logging into ElasticSearch: ",
                                              confirm_prompt="Confirm Password: ")
            self.register_install_strategy(
                execution_strategy.LogstashInstallStrategy(
                    listen_address=args.ls_addr,
                    elasticsearch_host=args.es_host,
                    elasticsearch_port=args.es_port,
                    elasticsearch_password=es_password,
                    heap_size_gigs=args.logstash_heap_size,
                    install_jdk=not args.skip_logstash_install_jdk,
                    check_elasticsearch_connection=not args.skip_check_elasticsearch_connection,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                ))
            self.install()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.LogstashUninstallStrategy(
                    stdout=not args.no_stdout,
                    prompt_user=not args.skip_logstash_uninstall_prompt
                )
            )
            self.uninstall()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.LogstashProcessStartStrategy(
                    stdout=not args.no_stdout,
                    status=True
                )
            )
            self.start()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.LogstashProcessStopStrategy(
                    stdout=not args.no_stdout,
                    status=True
                )
            )
            self.stop()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.LogstashProcessRestartStrategy(
                    stdout=not args.no_stdout,
                    status=True
                )
            )
            self.restart()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.LogstashProcessStatusStrategy()
            )
            self.status()


if __name__ == '__main__':
    ls_component = LogstashComponent()
    ls_component.install()
    ls_component.start()
    ls_component.stop()
    ls_component.status()
    ls_component.uninstall()
