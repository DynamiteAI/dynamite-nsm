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
                prompt_user=prompt_on_uninstall,
                stdout=stdout,
                verbose=verbose
            ),
            process_start_strategy=execution_strategy.LogstashProcessStartStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_stop_strategy=execution_strategy.LogstashProcessStopStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_restart_strategy=execution_strategy.LogstashProcessRestartStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
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
            change_password_strategy=None,
            install_strategy=None,
            uninstall_strategy=None,
            process_start_strategy=None,
            process_stop_strategy=None,
            process_restart_strategy=None,
            process_status_strategy=None
        )
        if args.action_name == "chpasswd":
            new_logstash_password = args.new_logstash_password
            if not new_logstash_password:
                new_logstash_password = prompt_password(
                    '[?] Enter the new password that LogStash uses to connect to ElasticSearch: ',
                    confirm_prompt="[?] Confirm Password: ")
            self.register_change_password_strategy(
                execution_strategy.LogStashChangePasswordStrategy(
                    new_password=new_logstash_password,
                    prompt_user=not args.skip_logstash_chpasswd_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_change_password_strategy()
        if args.action_name == "install":
            es_password = args.elastic_password
            if not es_password:
                es_password = prompt_password("[?] Enter the password for logging into ElasticSearch: ",
                                              confirm_prompt="[?] Confirm Password: ")
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
            self.execute_install_strategy()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.LogstashUninstallStrategy(
                    prompt_user=not args.skip_logstash_uninstall_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_uninstall_strategy()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.LogstashProcessStartStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_start_strategy()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.LogstashProcessStopStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_stop_strategy()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.LogstashProcessRestartStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_restart_strategy()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.LogstashProcessStatusStrategy()
            )
            self.execute_process_status_strategy()


if __name__ == '__main__':
    ls_component = LogstashComponent()
    ls_component.execute_install_strategy()
    ls_component.execute_process_start_strategy()
    ls_component.execute_process_stop_strategy()
    ls_component.execute_process_status_strategy()
    ls_component.execute_uninstall_strategy()
