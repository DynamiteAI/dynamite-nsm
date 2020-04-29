import getpass

from dynamite_nsm.utilities import prompt_password
from dynamite_nsm.components.base import component
from dynamite_nsm.components.elasticsearch import execution_strategy


class ElasticsearchComponent(component.BaseComponent):
    """
    ElasticSearch Component Wrapper intended for general use
    """

    def __init__(self, install_password='changeme', install_heap_size_gigs=4, install_jdk=True,
                 prompt_on_uninstall=True, stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="ElasticSearch",
            component_description="Store and search network events.",
            install_strategy=execution_strategy.ElasticsearchInstallStrategy(
                password=install_password,
                heap_size_gigs=install_heap_size_gigs,
                install_jdk=install_jdk,
                stdout=stdout,
                verbose=verbose
            ),
            uninstall_strategy=execution_strategy.ElasticsearchUninstallStrategy(
                prompt_user=prompt_on_uninstall,
                stdout=stdout,
                verbose=verbose
            ),
            process_start_strategy=execution_strategy.ElasticsearchProcessStartStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_stop_strategy=execution_strategy.ElasticsearchProcessStopStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose

            ),
            process_restart_strategy=execution_strategy.ElasticsearchProcessRestartStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_status_strategy=execution_strategy.ElasticsearchProcessStatusStrategy()
        )


class ElasticsearchCommandlineComponent(component.BaseComponent):
    """
    ElasticSearch Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="ElasticSearch",
            component_description="Store and search network events.",
            change_password_strategy=None,
            install_strategy=None,
            uninstall_strategy=None,
            process_start_strategy=None,
            process_stop_strategy=None,
            process_restart_strategy=None,
            process_status_strategy=None
        )
        if args.action_name == "chpasswd":
            old_es_password = args.old_elastic_password
            new_es_password = args.new_elastic_password
            if not old_es_password:
                old_es_password = getpass.getpass('[?] Enter the old ElasticSearch password: ')
            if not new_es_password:
                new_es_password = prompt_password('[?] Enter the new ElasticSearch password: ',
                                                  confirm_prompt="[?] Confirm Password: ")
            self.register_change_password_strategy(
                execution_strategy.ElasticsearchChangePasswordStrategy(
                    old_password=old_es_password,
                    new_password=new_es_password,
                    remote_host=args.es_host,
                    remote_port=args.es_port,
                    prompt_user=not args.skip_elastic_chpasswd_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_change_password_strategy()

        elif args.action_name == "install":
            es_password = args.elastic_password
            if not es_password:
                es_password = prompt_password("[?] Enter the password for logging into ElasticSearch: ",
                                              confirm_prompt="[?] Confirm Password: ")
            self.register_install_strategy(
                execution_strategy.ElasticsearchInstallStrategy(
                    password=es_password,
                    heap_size_gigs=args.elastic_heap_size,
                    install_jdk=not args.skip_elastic_install_jdk,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                ))
            self.execute_install_strategy()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.ElasticsearchUninstallStrategy(
                    prompt_user=not args.skip_elastic_uninstall_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_uninstall_strategy()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.ElasticsearchProcessStartStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_start_strategy()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.ElasticsearchProcessStopStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_stop_strategy()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.ElasticsearchProcessRestartStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_restart_strategy()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.ElasticsearchProcessStatusStrategy()
            )
            self.execute_process_status_strategy()


if __name__ == '__main__':
    es_component = ElasticsearchComponent()
    es_component.execute_install_strategy()
    es_component.execute_process_start_strategy()
    es_component.execute_process_stop_strategy()
    es_component.execute_process_status_strategy()
    es_component.execute_uninstall_strategy()
