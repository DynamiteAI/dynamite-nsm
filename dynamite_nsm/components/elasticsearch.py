from dynamite_nsm.components.base import exec_strategy
from dynamite_nsm.services.elasticsearch import install, process


class ElasticsearchInstallStrategy(exec_strategy.BaseExecStrategy):

    def __init__(self, password, heap_size_gigs, stdout, verbose):
        exec_strategy.BaseExecStrategy.__init__(self, strategy_name="Elasticsearch Install",
                                                strategy_description="Install and secure Elasticsearch.")
        self.add_function(
            install.install_elasticsearch, {
                "configuration_directory": "/etc/dynamite/elasticsearch/",
                "install_directory": "/opt/dynamite/elasticsearch/",
                "log_directory": "/var/log/dynamite/elasticsearch/",
                "password": str(password),
                "heap_size_gigs": int(heap_size_gigs),
                "install_jdk": False,
                "create_dynamite_user": True,
                "stdout": bool(stdout),
                "verbose": bool(verbose)

            }
        )


if __name__ == '__main__':
    es_elastic_install_strategy = ElasticsearchInstallStrategy(
        password="changeme",
        heap_size_gigs=4,
        stdout=True,
        verbose=True
    )

    es_elastic_install_strategy.execute_strategy()

