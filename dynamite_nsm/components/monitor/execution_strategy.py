import os
import sys
from dynamite_nsm import const
from dynamite_nsm.components.base import execution_strategy
from dynamite_nsm.services.kibana import install as kb_install
from dynamite_nsm.services.kibana import process as kb_process
from dynamite_nsm.services.logstash import install as mon_install
from dynamite_nsm.services.logstash import process as mon_process
from dynamite_nsm.services.elasticsearch import install as es_install
from dynamite_nsm.services.elasticsearch import process as es_process

from dynamite_nsm.utilities import check_socket, prompt_input


def print_message(msg):
    print(msg)


def remove_elasticsearch_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.ELASTICSEARCH_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def remove_logstash_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.LOGSTASH_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def remove_kibana_tar_archive():
    dir_path = os.path.join(const.INSTALL_CACHE, const.KIBANA_ARCHIVE_NAME)
    if os.path.exists(dir_path):
        os.remove(dir_path)


def check_elasticsearch_target(host, port, perform_check=True):
    if not perform_check:
        return
    if not check_socket(host, port):
        print("ElasticSearch does not appear to be started on: {}:{}.".format(host, port))
        if str(prompt_input('Continue? [y|N]: ')).lower() != 'y':
            exit(0)
    return


def prompt_monitor_uninstall(prompt_user=True, stdout=True):
    if prompt_user:
        sys.stderr.write(
            '[-] WARNING! Removing Monitor Will Delete All Saved Network Events and Corresponding Visualisations.\n')
        resp = prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return


def get_monitor_status():
    return (
            dict(
                elasticsearch=es_process.status(),
                logstash=mon_process.status(),
                kibana=kb_process.status()
            )
    )


class MonitorInstallStrategy(execution_strategy.BaseExecStrategy):

    def __init__(self, logstash_listen_address, kibana_listen_address, kibana_listen_port, elasticsearch_host,
                 elasticsearch_port, elasticsearch_password, elasticsearch_heap_size_gigs, logstash_heap_size_gigs,
                 install_jdk, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="monitor_install",
            strategy_description="Install ElasticSearch, LogStash, and Kibana on the same instance.",
            functions=(
                remove_elasticsearch_tar_archive,
                remove_logstash_tar_archive,
                remove_kibana_tar_archive,
                es_install.install_elasticsearch,
                es_process.start,
                mon_install.install_logstash,
                mon_process.stop,
                kb_install.install_kibana,
                kb_process.stop,
                es_process.stop,
                print_message,
                print_message
            ),
            arguments=(
                # remove_elasticsearch_tar_archive
                {},
                # remove_logstash_tar_archive
                {},
                # remove_kibana_tar_archive
                {},
                # es_install.install_elasticsearch
                {
                    "configuration_directory": "/etc/dynamite/elasticsearch/",
                    "install_directory": "/opt/dynamite/elasticsearch/",
                    "log_directory": "/var/log/dynamite/elasticsearch/",
                    "password": str(elasticsearch_password),
                    "heap_size_gigs": int(elasticsearch_heap_size_gigs),
                    "install_jdk": bool(install_jdk),
                    "create_dynamite_user": True,
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # es_process.start
                {
                    "stdout": False
                },
                # mon_install.install_logstash
                {
                    "configuration_directory": "/etc/dynamite/logstash/",
                    "install_directory": "/opt/dynamite/logstash/",
                    "log_directory": "/var/log/dynamite/logstash/",
                    "host": str(logstash_listen_address),
                    "elasticsearch_host": str(elasticsearch_host),
                    "elasticsearch_port": int(elasticsearch_port),
                    "elasticsearch_password": str(elasticsearch_password),
                    "heap_size_gigs": int(logstash_heap_size_gigs),
                    "install_jdk": False,
                    "create_dynamite_user": False,
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # mon_process.stop
                {
                    "stdout": False
                },
                # kb_install.install_kibana
                {
                    "configuration_directory": "/etc/dynamite/kibana/",
                    "install_directory": "/opt/dynamite/kibana/",
                    "log_directory": "/var/log/dynamite/kibana/",
                    "host": str(kibana_listen_address),
                    "port": int(kibana_listen_port),
                    "elasticsearch_host": str(elasticsearch_host),
                    "elasticsearch_port": int(elasticsearch_port),
                    "elasticsearch_password": str(elasticsearch_password),
                    "create_dynamite_user": True,
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # kb_process.stop
                {
                    "stdout": False
                },
                # es_process.stop
                {
                    "stdout": False
                },
                # print_message
                {
                    "msg": '[+] *** Monitor installed successfully. ***\n'
                },
                # print_message
                {
                    "msg": '[+] Next, Start your monitor: '
                           '\'dynamite monitor start\'.'
                }
            ),
            return_formats=(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None
            )
        )


class MonitorUninstallStrategy(execution_strategy.BaseExecStrategy):

    def __init__(self, stdout, prompt_user):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="logstash_uninstall",
            strategy_description="Uninstall LogStash.",
            functions=(
                prompt_monitor_uninstall,
                kb_install.uninstall_kibana,
                mon_install.uninstall_logstash,
                es_install.uninstall_elasticsearch,
                print_message
            ),
            arguments=(
                # prompt_user
                {
                    "prompt_user": bool(prompt_user),
                    "stdout": bool(stdout)
                },
                # kb_install.uninstall_kibana
                {
                    "stdout": bool(stdout),
                    "prompt_user": False
                },
                # mon_install.uninstall_logstash
                {
                    "stdout": bool(stdout),
                    "prompt_user": False
                },
                # es_install.uninstall_elasticsearch
                {
                    "stdout": bool(stdout),
                    "prompt_user": False
                },
                # print_message
                {
                    "msg": '[+] *** Monitor uninstalled successfully. ***\n'
                },
            ),
            return_formats=(
                None,
                None,
                None,
                None,
                None
            )
        )


class MonitorProcessStartStrategy(execution_strategy.BaseExecStrategy):

    def __init__(self, stdout, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="monitor_start",
            strategy_description="Start Monitor processes.",
            functions=(
                es_process.start,
                mon_process.start,
                kb_process.start
            ),
            arguments=(
                # es_process.start.start
                {
                    "stdout": stdout
                },
                # mon_process.start.start
                {
                    "stdout": stdout
                },
                # kb_process.start.start
                {
                    "stdout": stdout
                }
            ),
            return_formats=(
                None,
                None,
                None
            )

        )
        if status:
            self.add_function(get_monitor_status, {}, return_format="json")


class MonitorProcessStopStrategy(execution_strategy.BaseExecStrategy):

    def __init__(self, stdout, status):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="monitor_stop",
            strategy_description="Stop Monitor processes.",
            functions=(
                mon_process.stop,
                kb_process.stop,
                es_process.stop,
            ),
            arguments=(
                # mon_process.start.start
                {
                    "stdout": stdout
                },
                # kb_process.start.start
                {
                    "stdout": stdout
                },
                # es_process.start.start
                {
                    "stdout": stdout
                }
            ),
            return_formats=(
                None,
                None,
                None
            )
        )
        if status:
            self.add_function(get_monitor_status, {}, return_format="json")


class MonitorProcessRestartStrategy(execution_strategy.BaseExecStrategy):

    def __init__(self, stdout, status):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="monitor_restart",
            strategy_description="Restart Monitor processes.",
            functions=(
                mon_process.stop,
                kb_process.stop,
                es_process.stop,
                es_process.start,
                kb_process.start,
                mon_process.start,
            ),
            arguments=(
                # mon_process.stop
                {
                    "stdout": stdout
                },
                # kb_process.stop
                {
                    "stdout": stdout
                },
                # es_process.stop
                {
                    "stdout": stdout
                },
                # es_process.start
                {
                    "stdout": stdout
                },
                # kb_process.start
                {
                    "stdout": stdout
                },
                # mon_process.start
                {
                    "stdout": stdout
                }

            ),
            return_formats=(
                None,
                None,
                None,
                None,
                None,
                None
            )
        )
        if status:
            self.add_function(get_monitor_status, {}, return_format="json")


class MonitorProcessStatusStrategy(execution_strategy.BaseExecStrategy):

    def __init__(self):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="monitor_status",
            strategy_description="Get the status of the Monitor processes.",
            functions=(
                get_monitor_status
            ),
            arguments=(
                {},
            ),
            return_formats=(
                'json',
            )
        )


# Test Functions


def run_install_strategy():
    mon_install_strategy = MonitorInstallStrategy(
        logstash_listen_address="0.0.0.0",
        kibana_listen_address="0.0.0.0",
        kibana_listen_port=5601,
        elasticsearch_host="localhost",
        elasticsearch_port=9200,
        elasticsearch_password="changeme",
        elasticsearch_heap_size_gigs=4,
        logstash_heap_size_gigs=4,
        install_jdk=True,
        stdout=True,
        verbose=True
    )
    mon_install_strategy.execute_strategy()


def run_uninstall_strategy():
    mon_uninstall_strategy = MonitorUninstallStrategy(
        stdout=True,
        prompt_user=False
    )
    mon_uninstall_strategy.execute_strategy()


def run_process_start_strategy():
    mon_start_strategy = MonitorProcessStartStrategy(
        stdout=True,
        status=True
    )
    mon_start_strategy.execute_strategy()


def run_process_stop_strategy():
    mon_stop_strategy = MonitorProcessStopStrategy(
        stdout=True,
        status=True
    )
    mon_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    mon_restart_strategy = MonitorProcessRestartStrategy(
        stdout=True,
        status=True
    )
    mon_restart_strategy.execute_strategy()


def run_process_status_strategy():
    mon_status_strategy = MonitorProcessStatusStrategy()
    mon_status_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    run_process_start_strategy()
    run_process_stop_strategy()
    run_process_restart_strategy()
    run_process_status_strategy()
    run_uninstall_strategy()
    pass
