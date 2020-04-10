from dynamite_nsm.components.base import component
from dynamite_nsm.components.elasticsearch import execution_strategy


class ElasticComponent(component.BaseComponent):

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


if __name__ == '__main__':
    es_component = ElasticComponent()
    es_component.install()
    es_component.start()
    es_component.stop()
    es_component.status()
    es_component.uninstall()
