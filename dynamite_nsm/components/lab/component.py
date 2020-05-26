from dynamite_nsm.utilities import prompt_password
from dynamite_nsm.components.base import component
from dynamite_nsm.components.lab import execution_strategy


class LabComponent(component.BaseComponent):
    """
    Lab Component Wrapper intended for general use
    """

    def __init__(self, jupyterhub_host='0.0.0.0', jupyterhub_password='changeme', elasticsearch_host="localhost",
                 elasticsearch_port=9200, elasticsearch_password='changeme', prompt_on_uninstall=True,
                 check_elasticsearch_connection=True, stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="Lab",
            component_description="Analyze your network traffic with Jupyter Notebooks.",
            install_strategy=execution_strategy.LabInstallStrategy(
                jupyterhub_host=jupyterhub_host,
                jupyterhub_password=jupyterhub_password,
                elasticsearch_host=elasticsearch_host,
                elasticsearch_port=elasticsearch_port,
                elasticsearch_password=elasticsearch_password,
                check_elasticsearch_connection=check_elasticsearch_connection,
                stdout=stdout,
                verbose=verbose
            ),
            uninstall_strategy=execution_strategy.LabUninstallStrategy(
                prompt_user=prompt_on_uninstall,
                stdout=stdout,
                verbose=verbose
            ),
            process_start_strategy=execution_strategy.LabProcessStartStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_stop_strategy=execution_strategy.LabProcessStopStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_restart_strategy=execution_strategy.LabProcessRestartStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_status_strategy=execution_strategy.LabProcessStatusStrategy()
        )


class LabCommandlineComponent(component.BaseComponent):
    """
    Lab Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="Lab",
            component_description="Analyze your network traffic with Jupyter Notebooks.",
            install_strategy=None,
            uninstall_strategy=None,
            process_start_strategy=None,
            process_stop_strategy=None,
            process_restart_strategy=None,
            process_status_strategy=None
        )

        if args.action_name == "install":
            es_password = args.elastic_password
            jupyter_password = args.jupyter_password
            if not es_password:
                es_password = prompt_password("[?] Enter the password for logging into ElasticSearch: ",
                                              confirm_prompt="[?] Confirm Password: ")
            if not jupyter_password:
                es_password = prompt_password("[?] Enter the password for logging into JupyterHub: ",
                                              confirm_prompt="[?] Confirm Password: ")
            self.register_install_strategy(
                execution_strategy.LabInstallStrategy(
                    jupyterhub_host=args.jupyter_addr,
                    jupyterhub_password=args.jupyter_password,
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
                execution_strategy.LabUninstallStrategy(
                    prompt_user=not args.skip_lab_uninstall_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_uninstall_strategy()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.LabProcessStartStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_start_strategy()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.LabProcessStopStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_stop_strategy()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.LabProcessRestartStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_restart_strategy()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.LabProcessStatusStrategy()
            )
            self.execute_process_status_strategy()


if __name__ == '__main__':
    lab_component = LabComponent()
    lab_component.execute_install_strategy()
    lab_component.execute_process_start_strategy()
    lab_component.execute_process_stop_strategy()
    lab_component.execute_process_status_strategy()
    lab_component.execute_uninstall_strategy()
