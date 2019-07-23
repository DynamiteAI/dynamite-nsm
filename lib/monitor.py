import sys
from lib import utilities
from lib.services import elasticsearch, logstash, kibana


def install_monitor():
    """
    Installs Logstash (with ElastiFlow templates modified to work with Zeek), ElasticSearch, and Kibana.

    :return: True, if installation succeeded
    """
    if utilities.get_memory_available_bytes() < 10 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite standalone monitor requires '
                         'at-least 10GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes() / (1024 ** 3)
        ))
        return False
    utilities.create_dynamite_user('password')
    utilities.download_java(stdout=True)
    utilities.extract_java(stdout=True)
    utilities.setup_java()
    es_installer = elasticsearch.ElasticInstaller()
    es_pre_profiler = elasticsearch.ElasticProfiler()
    es_process = elasticsearch.ElasticProcess()
    ls_installer = logstash.LogstashInstaller()
    ls_pre_profiler = logstash.LogstashProfiler()
    kb_installer = kibana.KibanaInstaller('0.0.0.0', 5601)
    kb_pre_profiler = kibana.KibanaProfiler()
    if not es_pre_profiler.is_installed:
        sys.stdout.write('[+] Installing Elasticsearch on localhost.\n')
        if not es_pre_profiler.is_downloaded:
            es_installer.download_elasticsearch(stdout=True)
            es_installer.extract_elasticsearch(stdout=True)
        es_installer.setup_elasticsearch(stdout=True)
        if not elasticsearch.ElasticProfiler().is_installed:
            sys.stderr.write('[-] ElasticSearch failed to install on localhost.\n')
            return False
    sys.stdout.write('[+] Starting ElasticSearch on localhost.\n')
    es_process.start()
    if not ls_pre_profiler.is_installed:
        if not ls_pre_profiler.is_downloaded:
            ls_installer.download_logstash(stdout=True)
            ls_installer.extract_logstash(stdout=True)
        ls_installer.setup_logstash(stdout=True)
        if not logstash.LogstashProfiler().is_installed:
            sys.stderr.write('[-] LogStash failed to install on localhost.\n')
            return False
    if not kb_pre_profiler.is_installed and elasticsearch.ElasticProfiler().is_installed:
        sys.stdout.write('[+] Installing Kibana on localhost.\n')
        if not kb_pre_profiler.is_downloaded:
            kb_installer.download_kibana(stdout=True)
            kb_installer.extract_kibana(stdout=True)
        kb_installer.setup_kibana(stdout=True)
        if not kibana.KibanaProfiler().is_installed:
            sys.stderr.write('[-] Kibana failed to install on localhost.\n')
            return False
        sys.stdout.write('[+] Monitor installation complete. Start the monitor: \'dynamite.py start monitor\'.\n')
        sys.stdout.flush()
    return True


def start_monitor():
    """
    Starts ElasticSearch, Logstash, and Kibana on localhost

    :return: True, if successfully started
    """
    es_profiler = elasticsearch.ElasticProfiler()
    ls_profiler = logstash.LogstashProfiler()
    kb_profiler = kibana.KibanaProfiler()
    es_process = elasticsearch.ElasticProcess()
    ls_process = logstash.LogstashProcess()
    kb_process = kibana.KibanaProcess()
    if not (es_profiler.is_installed or ls_profiler.is_installed or kb_profiler.is_installed):
        sys.stderr.write('[-] Could not start monitor. Is it installed?\n')
        sys.stderr.write('[-] dynamite.py install monitor\n')
        return False
    sys.stdout.write('[+] Starting monitor processes.\n')
    if not es_profiler.is_running:
        sys.stdout.write('[+] Starting Elasticsearch on localhost\n')
        es_process.start(stdout=True)
    if not ls_profiler.is_running:
        sys.stdout.write('[+] Starting Logstash on localhost\n')
        ls_process.start(stdout=True)
    if not kb_profiler.is_running:
        sys.stdout.write('[+] Starting Kibana on localhost\n')
        kb_process.start(stdout=True)
    if not elasticsearch.ElasticProfiler().is_running:
        sys.stderr.write('[-] Could not start monitor.elasticsearch.\n')
        return False
    elif not logstash.LogstashProfiler().is_running:
        sys.stderr.write('[-] Could not start monitor.logstash.\n')
        return False
    elif not kibana.KibanaProfiler().is_running:
        sys.stderr.write('[-] Could not start monitor.kibana.\n')
        return False
    return True


def status_monitor():
    """
    Retrieve the status of the monitor processes

    :return: A tuple where the first element is elasticsearch status (dict), second is logstash status (dict),
    and third is Kibana status.
    """
    es_profiler = elasticsearch.ElasticProfiler()
    ls_profiler = logstash.LogstashProfiler()
    kb_profiler = kibana.KibanaProfiler()
    es_process = elasticsearch.ElasticProcess()
    ls_process = logstash.LogstashProcess()
    kb_process = kibana.KibanaProcess()
    if not (es_profiler.is_installed or ls_profiler.is_installed or kb_profiler.is_installed):
        sys.stderr.write('[-] Could not start monitor. Is it installed?\n')
        sys.stderr.write('[-] dynamite.py install monitor\n')
        return False
    return es_process.status(), ls_process.status(), kb_process.status()


def stop_monitor():
    """
    Stops ElasticSearch, Logstash, and Kibana on localhost

    :return: True, if successfully stopped
    """
    es_profiler = elasticsearch.ElasticProfiler()
    ls_profiler = logstash.LogstashProfiler()
    kb_profiler = kibana.KibanaProfiler()
    es_process = elasticsearch.ElasticProcess()
    ls_process = logstash.LogstashProcess()
    kb_process = kibana.KibanaProcess()
    if not (es_profiler.is_installed or ls_profiler.is_installed or kb_profiler.is_installed):
        sys.stderr.write('[-] Could not start monitor. Is it installed?\n')
        sys.stderr.write('[-] dynamite.py install monitor\n')
        return False
    sys.stdout.write('[+] Stopping monitor processes.\n')
    if not es_process.stop(stdout=True):
        sys.stderr.write('[-] Could not stop monitor.elasticsearch.\n')
        return False
    elif not ls_process.stop(stdout=True):
        sys.stderr.write('[-] Could not stop monitor.logstash.\n')
        return False
    elif not kb_process.stop(stdout=True):
        sys.stderr.write('[-] Could not stop monitor.kibana.\n')
        return False
    return True



