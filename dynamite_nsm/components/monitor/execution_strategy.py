import os
import sys
from dynamite_nsm import const
from dynamite_nsm.components.base import execution_strategy
from dynamite_nsm.services.kibana import install as kb_install
from dynamite_nsm.services.kibana import process as kb_process
from dynamite_nsm.services.kibana import profile as kb_profile
from dynamite_nsm.services.logstash import install as ls_install
from dynamite_nsm.services.logstash import process as ls_process
from dynamite_nsm.services.logstash import profile as ls_profile
from dynamite_nsm.services.elasticsearch import install as es_install
from dynamite_nsm.services.elasticsearch import process as es_process
from dynamite_nsm.services.elasticsearch import profile as es_profile

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
            logstash=ls_process.status(),
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
        )
        
        self.add_function(func=remove_elasticsearch_tar_archive, argument_dict={}, return_format=None)

        self.add_function(func=remove_logstash_tar_archive, argument_dict={}, return_format=None)

        self.add_function(func=remove_kibana_tar_archive, argument_dict={}, return_format=None)

        if not es_profile.ProcessProfiler().is_installed:
            self.add_function(func=es_install.install_elasticsearch, argument_dict={
                "configuration_directory": "/etc/dynamite/elasticsearch/",
                "install_directory": "/opt/dynamite/elasticsearch/",
                "log_directory": "/var/log/dynamite/elasticsearch/",
                "password": str(elasticsearch_password),
                "heap_size_gigs": int(elasticsearch_heap_size_gigs),
                "install_jdk": bool(install_jdk),
                "create_dynamite_user": True,
                "stdout": bool(stdout),
                "verbose": bool(verbose)
            }, return_format=None)
        else:
            self.add_function(func=print_message, argument_dict={
                "msg": 'Skipping ElasticSearch installation; already installed.'
            }, return_format=None)

        self.add_function(func=es_process.start, argument_dict={
            "stdout": False
        }, return_format=None)

        if not ls_profile.ProcessProfiler().is_installed:
            self.add_function(func=ls_install, argument_dict={
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
            }, return_format=None)
        else:
            self.add_function(func=print_message, argument_dict={
                "msg": 'Skipping LogStash installation; already installed.'
            }, return_format=None)

        self.add_function(func=ls_process.stop, argument_dict={
            "stdout": False
        }, return_format=None)

        if not kb_profile.ProcessProfiler().is_installed:
            self.add_function(func=kb_install, argument_dict={
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
            }, return_format=None)
        else:
            self.add_function(func=print_message, argument_dict={
                "msg": 'Skipping Kibana installation; already installed.'
            }, return_format=None)

        self.add_function(func=kb_process.stop, argument_dict={
            "stdout": False
        }, return_format=None)
        
        self.add_function(func=es_process.stop, argument_dict={
            "stdout": False
        }, return_format=None)
        
        self.add_function(func=print_message, argument_dict={
            "msg": '[+] *** Monitor installed successfully. ***\n'
        }, return_format=None)
        
        self.add_function(func=print_message, argument_dict={
            "msg": '[+] Next, Start your monitor: '
                   '\'dynamite monitor start\'.'
        }, return_format=None)


class MonitorUninstallStrategy(execution_strategy.BaseExecStrategy):

    def __init__(self, stdout, prompt_user):
        execution_strategy.BaseExecStrategy.__init__(
            self, strategy_name="logstash_uninstall",
            strategy_description="Uninstall LogStash.",
            functions=(
                prompt_monitor_uninstall,
                kb_install.uninstall_kibana,
                ls_install.uninstall_logstash,
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
                # ls_install.uninstall_logstash
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
                ls_process.start,
                kb_process.start
            ),
            arguments=(
                # es_process.start.start
                {
                    "stdout": stdout
                },
                # ls_process.start.start
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
                ls_process.stop,
                kb_process.stop,
                es_process.stop,
            ),
            arguments=(
                # ls_process.start.start
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
                ls_process.stop,
                kb_process.stop,
                es_process.stop,
                es_process.start,
                kb_process.start,
                ls_process.start,
            ),
            arguments=(
                # ls_process.stop
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
                # ls_process.start
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
    ls_install_strategy = MonitorInstallStrategy(
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
    ls_install_strategy.execute_strategy()


def run_uninstall_strategy():
    ls_uninstall_strategy = MonitorUninstallStrategy(
        stdout=True,
        prompt_user=False
    )
    ls_uninstall_strategy.execute_strategy()


def run_process_start_strategy():
    ls_start_strategy = MonitorProcessStartStrategy(
        stdout=True,
        status=True
    )
    ls_start_strategy.execute_strategy()


def run_process_stop_strategy():
    ls_stop_strategy = MonitorProcessStopStrategy(
        stdout=True,
        status=True
    )
    ls_stop_strategy.execute_strategy()


def run_process_restart_strategy():
    ls_restart_strategy = MonitorProcessRestartStrategy(
        stdout=True,
        status=True
    )
    ls_restart_strategy.execute_strategy()


def run_process_status_strategy():
    ls_status_strategy = MonitorProcessStatusStrategy()
    ls_status_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    run_process_start_strategy()
    run_process_stop_strategy()
    run_process_restart_strategy()
    run_process_status_strategy()
    run_uninstall_strategy()
    pass
