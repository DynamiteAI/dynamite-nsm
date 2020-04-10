import argparse

from dynamite_nsm.utilities import prompt_password
from dynamite_nsm.components.base import component
from dynamite_nsm.components.elasticsearch import execution_strategy


class ElasticsearchComponent(component.BaseComponent):

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
                stdout=stdout,
                prompt_user=prompt_on_uninstall
            ),
            process_start_strategy=execution_strategy.ElasticsearchProcessStartStrategy(
                stdout=stdout,
                status=True
            ),
            process_stop_strategy=execution_strategy.ElasticsearchProcessStopStrategy(
                stdout=stdout,
                status=True
            ),
            process_restart_strategy=execution_strategy.ElasticsearchProcessRestartStrategy(
                stdout=stdout,
                status=True
            ),
            process_status_strategy=execution_strategy.ElasticsearchProcessStatusStrategy()
        )


class ElasticsearchCommandlineComponent(component.BaseComponent):

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="ElasticSearch",
            component_description="Store and search network events.",
        )

        if args.action_name == "install":
            es_password = args.elastic_password
            if not es_password:
                es_password = prompt_password("Enter the password for logging into ElasticSearch: ",
                                confirm_prompt="Confirm Password: ")
            self.register_install_strategy(
                execution_strategy.ElasticsearchInstallStrategy(
                    password=es_password,
                    heap_size_gigs=args.elastic_heap_size,
                    install_jdk=not args.elastic_install_jdk,
                    stdout=not args.silent,
                    verbose=args.verbose and not args.silent
                ))
            self.install()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.ElasticsearchUninstallStrategy(
                    stdout=not args.silent,
                    prompt_user=not args.skip_elastic_uninstall_prompt
                )
            )
            self.uninstall()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.ElasticsearchProcessStartStrategy(
                    stdout=not args.silent,
                    status=True
                )
            )
            self.start()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.ElasticsearchProcessStopStrategy(
                    stdout=not args.silent,
                    status=True
                )
            )
            self.stop()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.ElasticsearchProcessRestartStrategy(
                    stdout=not args.silent,
                    status=True
                )
            )
            self.restart()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.ElasticsearchProcessStatusStrategy()
            )
            self.status()


if __name__ == '__main__':
    es_component = ElasticsearchComponent()
    es_component.install()
    es_component.start()
    es_component.stop()
    es_component.status()
    es_component.uninstall()
