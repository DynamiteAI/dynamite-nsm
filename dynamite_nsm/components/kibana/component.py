from dynamite_nsm.utilities import prompt_password
from dynamite_nsm.components.base import component
from dynamite_nsm.components.kibana import execution_strategy


class KibanaComponent(component.BaseComponent):
    """
    Kibana Component Wrapper intended for general use
    """

    def __init__(self, listen_address="0.0.0.0", listen_port=5601, elasticsearch_host="localhost",
                 elasticsearch_port=9200, elasticsearch_password='changeme', prompt_on_uninstall=True,
                 check_elasticsearch_connection=True, stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="Kibana",
            component_description="Visualise and make sense of your network data.",
            install_strategy=execution_strategy.KibanaInstallStrategy(
                listen_address=listen_address,
                listen_port=listen_port,
                elasticsearch_host=elasticsearch_host,
                elasticsearch_port=elasticsearch_port,
                elasticsearch_password=elasticsearch_password,
                check_elasticsearch_connection=check_elasticsearch_connection,
                stdout=stdout,
                verbose=verbose
            ),
            uninstall_strategy=execution_strategy.KibanaUninstallStrategy(
                prompt_user=prompt_on_uninstall,
                stdout=stdout,
                verbose=verbose
            ),
            process_start_strategy=execution_strategy.KibanaProcessStartStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_stop_strategy=execution_strategy.KibanaProcessStopStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_restart_strategy=execution_strategy.KibanaProcessRestartStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_status_strategy=execution_strategy.KibanaProcessStatusStrategy()
        )


class KibanaCommandlineComponent(component.BaseComponent):
    """
    Kibana Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="Kibana",
            component_description="Visualise and make sense of your network data.",
            change_password_strategy=None,
            install_strategy=None,
            uninstall_strategy=None,
            process_start_strategy=None,
            process_stop_strategy=None,
            process_restart_strategy=None,
            process_status_strategy=None
        )

        if args.action_name == "chpasswd":
            new_kibana_password = args.new_kibana_password
            if not new_kibana_password:
                new_kibana_password = prompt_password(
                    '[?] Enter the new password that Kibana uses to connect to ElasticSearch: ',
                    confirm_prompt="[?] Confirm Password: ")
            self.register_change_password_strategy(
                execution_strategy.KibanaChangePasswordStrategy(
                    new_password=new_kibana_password,
                    prompt_user=not args.skip_kibana_chpasswd_prompt,
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
                execution_strategy.KibanaInstallStrategy(
                    listen_address=args.kb_addr,
                    listen_port=args.kb_port,
                    elasticsearch_host=args.es_host,
                    elasticsearch_port=args.es_port,
                    elasticsearch_password=es_password,
                    check_elasticsearch_connection=not args.skip_check_elasticsearch_connection,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                ))
            self.execute_install_strategy()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.KibanaUninstallStrategy(
                    prompt_user=not args.skip_kibana_uninstall_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_uninstall_strategy()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.KibanaProcessStartStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_process_start_strategy()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.KibanaProcessStopStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_process_stop_strategy()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.KibanaProcessRestartStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_process_restart_strategy()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.KibanaProcessStatusStrategy()
            )
            self.execute_process_status_strategy()


if __name__ == '__main__':
    kb_component = KibanaComponent()
    kb_component.execute_install_strategy()
    kb_component.execute_process_start_strategy()
    kb_component.execute_process_stop_strategy()
    kb_component.execute_process_status_strategy()
    kb_component.execute_uninstall_strategy()
