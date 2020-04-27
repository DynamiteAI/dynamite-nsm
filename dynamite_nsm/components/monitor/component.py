from dynamite_nsm.utilities import prompt_password
from dynamite_nsm.components.base import component
from dynamite_nsm.components.monitor import execution_strategy


class MonitorComponent(component.BaseComponent):
    """
    Monitor Component Wrapper intended for general use
    """

    def __init__(self, logstash_listen_address='0.0.0.0', kibana_listen_address='0.0.0.0', kibana_listen_port=5601,
                 elasticsearch_host="localhost", elasticsearch_port=9200, elasticsearch_password='changeme',
                 logstash_heap_size_gigs=4, elasticsearch_heap_size_gigs=4, install_jdk=True, prompt_on_uninstall=True,
                 stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="Monitor",
            component_description="Process, store, and visualise network data with a standalone Monitor (ElasticStack)."
                                  "",
            install_strategy=execution_strategy.MonitorInstallStrategy(
                logstash_heap_size_gigs=logstash_heap_size_gigs,
                logstash_listen_address=logstash_listen_address,
                kibana_listen_address=kibana_listen_address,
                kibana_listen_port=kibana_listen_port,
                elasticsearch_heap_size_gigs=elasticsearch_heap_size_gigs,
                elasticsearch_host=elasticsearch_host,
                elasticsearch_port=elasticsearch_port,
                elasticsearch_password=elasticsearch_password,
                install_jdk=install_jdk,
                stdout=stdout,
                verbose=verbose
            ),
            uninstall_strategy=execution_strategy.MonitorUninstallStrategy(
                stdout=stdout,
                verbose=verbose,
                prompt_user=prompt_on_uninstall
            ),
            process_start_strategy=execution_strategy.MonitorProcessStartStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_stop_strategy=execution_strategy.MonitorProcessStopStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_restart_strategy=execution_strategy.MonitorProcessRestartStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_status_strategy=execution_strategy.MonitorProcessStatusStrategy()
        )


class MonitorCommandlineComponent(component.BaseComponent):
    """
    Monitor Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="Monitor",
            component_description="Process, store, and visualise network data with a standalone Monitor (ElasticStack)."
                                  "",
        )

        if args.action_name == "install":
            es_password = args.elastic_password
            if not es_password:
                es_password = prompt_password("Enter the password for logging into ElasticSearch: ",
                                              confirm_prompt="Confirm Password: ")
            self.register_install_strategy(
                execution_strategy.MonitorInstallStrategy(
                    logstash_heap_size_gigs=args.ls_heap_size,
                    logstash_listen_address=args.ls_addr,
                    kibana_listen_address=args.kb_addr,
                    kibana_listen_port=args.kb_port,
                    elasticsearch_heap_size_gigs=args.elastic_heap_size,
                    elasticsearch_host=args.es_host,
                    elasticsearch_port=args.es_port,
                    elasticsearch_password=es_password,
                    install_jdk=not args.skip_monitor_install_jdk,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                ))
            self.install()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.MonitorUninstallStrategy(
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                    prompt_user=not args.skip_monitor_uninstall_prompt
                )
            )
            self.uninstall()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.MonitorProcessStartStrategy(
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                    status=True
                )
            )
            self.start()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.MonitorProcessStopStrategy(
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                    status=True
                )
            )
            self.stop()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.MonitorProcessRestartStrategy(
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                    status=True
                )
            )
            self.restart()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.MonitorProcessStatusStrategy()
            )
            self.status()


if __name__ == '__main__':
    mon_component = MonitorComponent()
    mon_component.install()
    mon_component.start()
    mon_component.stop()
    mon_component.status()
    mon_component.uninstall()
