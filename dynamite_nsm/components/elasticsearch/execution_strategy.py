import os
from dynamite_nsm import const
from dynamite_nsm.components.base import execution_strategy
from dynamite_nsm.services.elasticsearch import install, process


def print_message(msg):
    print(msg)


def remove_elasticsearch_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


class ElasticsearchInstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to install elasticsearch
    """

    def __init__(self, password, heap_size_gigs, install_jdk, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="elasticsearch_install",
            strategy_description="Install and secure ElasticSearch.",
            functions=(
                remove_elasticsearch_tar_archive,
                install.install_elasticsearch,
                process.stop,
                print_message,
                print_message
            ),
            arguments=(
                # remove_elasticsearch_tar_archive
                {},
                # install.install_elasticsearch
                {
                    "configuration_directory": "/etc/dynamite/elasticsearch/",
                    "install_directory": "/opt/dynamite/elasticsearch/",
                    "log_directory": "/var/log/dynamite/elasticsearch/",
                    "password": str(password),
                    "heap_size_gigs": int(heap_size_gigs),
                    "install_jdk": bool(install_jdk),
                    "create_dynamite_user": True,
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },

                # process.stop
                {
                    "stdout": False
                },

                # print_message
                {
                    "msg": '[+] *** ElasticSearch installed successfully. ***\n'
                },
                # print_message
                {
                    "msg": '[+] Next, Start your cluster: '
                           '\'dynamite elasticsearch start\'.'
                }
            ),
            return_formats=(
                None,
                None,
                None,
                None,
                None
            ))


class ElasticsearchUninstallStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to uninstall elasticsearch
    """

    def __init__(self, prompt_user, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="elasticsearch_uninstall",
            strategy_description="Uninstall ElasticSearch.",
            functions=(
                install.uninstall_elasticsearch,
                print_message
            ),
            arguments=(
                # install.uninstall_elasticsearch
                {
                    "prompt_user": bool(prompt_user),
                    "stdout": bool(stdout),
                    "verbose": bool(verbose),
                },

                # print_message
                {
                    "msg": '*** ElasticSearch uninstalled successfully. ***'
                },
            ),
            return_formats=(
                None,
                None
            )
        )


class ElasticsearchProcessStartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to start elasticsearch
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="elasticsearch_start",
            strategy_description="Start ElasticSearch process.",
            functions=(
                process.start,
            ),
            arguments=(
                # process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
            ),
            return_formats=(
                None,
            )

        )
        if status:
            self.add_function(process.status, {}, return_format="json")


class ElasticsearchProcessStopStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to stop elasticsearch
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="elasticsearch_stop",
            strategy_description="Stop ElasticSearch process.",
            functions=(
                process.stop,
            ),
            arguments=(
                # process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
            ),
            return_formats=(
                None,
            )

        )
        if status:
            self.add_function(process.status, {}, return_format="json")


class ElasticsearchProcessRestartStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to restart elasticsearch
    """

    def __init__(self, status, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="elasticsearch_restart",
            strategy_description="Restart ElasticSearch process.",
            functions=(
                process.stop,
                process.start,
            ),
            arguments=(
                # process.start
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },

                # process.stop
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
            ),
            return_formats=(
                None,
                None
            )
        )
        if status:
            self.add_function(process.status, {}, return_format="json")


class ElasticsearchProcessStatusStrategy(execution_strategy.BaseExecStrategy):
    """
    Steps to get the status of elasticsearch
    """

    def __init__(self):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="elasticsearch_status",
            strategy_description="Get the status of the ElasticSearch process.",
            functions=(
                process.status,
            ),
            arguments=(
                # process.status
                {},
            ),
            return_formats=(
                'json',
            )
        )


# Test Functions


def run_install_strategy():
    es_install_strategy = ElasticsearchInstallStrategy(
        password="changeme",
        heap_size_gigs=4,
        install_jdk=False,
        stdout=True,
        verbose=True
    )
    es_install_strategy.execute_strategy()


def run_uninstall_strategy():
    es_uninstall_strategy = ElasticsearchUninstallStrategy(
        stdout=True,
        prompt_user=False
    )
    es_uninstall_strategy.execute_strategy()


def run_process_start_strategy():
    es_start_strategy = ElasticsearchProcessStartStrategy(
        stdout=True,
        status=True
    )
    es_start_strategy.execute_strategy()


def run_process_stop_strategy():
    es_stop_strategy = ElasticsearchProcessStopStrategy(
        stdout=True,
        status=True
    )
    es_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    es_restart_strategy = ElasticsearchProcessRestartStrategy(
        stdout=True,
        status=True
    )
    es_restart_strategy.execute_strategy()


def run_process_status_strategy():
    es_status_strategy = ElasticsearchProcessStatusStrategy()
    es_status_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    run_process_start_strategy()
    run_process_stop_strategy()
    run_process_restart_strategy()
    run_process_status_strategy()
    run_uninstall_strategy()
    pass
