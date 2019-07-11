import sys
import json
import argparse
import traceback

from lib import zeek
from lib import pf_ring
from lib import filebeat
from lib import logstash
from lib import utilities
from lib import elasticsearch


def _parse_cmdline():
    parser = argparse.ArgumentParser(
        description='Install/Configure the Dynamite Analysis Framework.'
    )
    parser.add_argument('command', metavar='command', type=str,
                        help='An action to perform [prepare|install|start|stop|status]')
    parser.add_argument('component', metavar='component', type=str,
                        help='The component to perform an action against [agent|logstash|elasticsearch]')
    parser.add_argument('--host', type=str, dest='host', required='point' in sys.argv, help='A valid Ipv4/Ipv6 address or hostname')
    parser.add_argument('--port', type=int, dest='port', required='point' in sys.argv, help='A valid port [1-65535]')
    return parser.parse_args()


def install_elasticsearch():
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite ElasticSearch requires at-least 6GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes()/(1024 ** 3)
        ))
        sys.exit(1)
    try:
        es_installer = elasticsearch.ElasticInstaller()
        utilities.download_java(stdout=True)
        utilities.extract_java(stdout=True)
        utilities.setup_java()
        utilities.create_dynamite_user('password')
        es_installer.download_elasticsearch(stdout=True)
        es_installer.extract_elasticsearch(stdout=True)
        es_installer.setup_elasticsearch(stdout=True)
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install ElasticSearch: ')
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    sys.stdout.write('[+] *** ElasticSearch installed successfully. ***\n\n')
    sys.stdout.write('[+] Next, Start your cluster: \'dynamite.py start elasticsearch\'.\n')
    sys.stdout.flush()
    sys.exit(0)


def install_logstash():
    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite Logstash requires at-least 6GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes()/(1024 ** 3)
        ))
        sys.exit(1)
    try:
        ls_installer = logstash.LogstashInstaller()
        utilities.download_java(stdout=True)
        utilities.extract_java(stdout=True)
        utilities.setup_java()
        utilities.create_dynamite_user('password')
        ls_installer.download_logstash(stdout=True)
        ls_installer.extract_logstash(stdout=True)
        ls_installer.setup_logstash(stdout=True)
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install LogStash: ')
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    sys.stdout.write('[+] *** LogStash + ElastiFlow (w/ Zeek Support) installed successfully. ***\n\n')
    sys.stdout.write('[+] Next, Start your collector: \'dynamite.py start logstash\'.\n')
    sys.stdout.flush()
    sys.exit(0)


def install_agent():
    zeek_installer = zeek.ZeekInstaller()
    if not zeek_installer.install_dependencies():
        sys.stderr.write('[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
        sys.exit(1)
    zeek_installer.download_zeek(stdout=True)
    zeek_installer.extract_zeek(stdout=True)
    zeek_installer.setup_zeek(stdout=True)
    filebeat_installer = filebeat.FileBeatInstaller()
    filebeat_installer.download_filebeat(stdout=True)
    filebeat_installer.extract_filebeat(stdout=True)
    filebeat_installer.setup_filebeat(stdout=True)


def status_agent():
    zeek_p = zeek.ZeekProcess()
    filebeat_p = filebeat.FileBeatProcess()
    pf_ring_prof = pf_ring.PFRingProfiler()
    agent_status =  dict(
        agent_processes={
            'zeek': zeek_p.status(),
            'pf_ring': pf_ring_prof.get_profile()
        }
    )
    sys.stdout.write(json.dumps(agent_status, indent=1) + '\n')


def point_agent(host, port):
    filebeat_config = filebeat.FileBeatConfigurator()
    filebeat_config.set_logstash_targets(['{}:{}'.format(host, port)])
    filebeat_config.write_config()
    sys.stdout.write('[+] Agent is now pointing to Logstash [{}:{}]\n'.format(host, port))
    sys.stdout.write('[+] Agent must be restarted for changes to take effect.\n')


def start_agent():
    sys.stdout.write('[+] Starting agent processes.\n')
    zeek_p = zeek.ZeekProcess()
    if not zeek_p.start(stdout=True):
        sys.stderr.write('[-] Could not start agent.zeek_process.\n')
        sys.exit(1)
    filebeat_p = filebeat.FileBeatProcess()
    if not filebeat_p.start(stdout=True):
        sys.stderr.write('[-] Could not start agent.filebeat.\n')
        sys.exit(1)
    sys.exit(0)


def stop_agent():
    sys.stdout.write('[+] Stopping agent processes.\n')
    zeek_p = zeek.ZeekProcess()
    if not zeek_p.stop(stdout=True):
        sys.stderr.write('[-] Could not stop agent.zeek_process.\n')
        sys.exit(1)
    filebeat_p = filebeat.FileBeatProcess()
    if not filebeat_p.stop(stdout=True):
        sys.stderr.write('[-] Could not stop agent.filebeat.\n')
        sys.exit(1)
    sys.exit(0)


def prepare_agent():
    pf_ring_install = pf_ring.PFRingInstaller()
    if not pf_ring_install.install_dependencies():
        sys.stderr.write('[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
        sys.exit(1)
    sys.stdout.write('[+] *** Development Kernel Packages & Build Tools Installed. Please Reboot ***\n\n')
    sys.stdout.write('[+] After reboot, continue installation with: \'dynamite.py install monitor\'.\n')
    sys.stdout.flush()
    sys.exit(0)


if __name__ == '__main__':
    args = _parse_cmdline()
    if not utilities.is_root():
        sys.stderr.write('[-] This script must be run as root.\n')
        sys.exit(1)
    if args.command == 'point':
        if args.component == 'agent':
            point_agent(args.host, args.port)
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'prepare':
        if args.component == 'agent':
            prepare_agent()
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'install':
        if args.component == 'elasticsearch':
            install_elasticsearch()
        elif args.component == 'logstash':
            install_logstash()
        elif args.component == 'agent':
            install_agent()
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'start':
        if args.component == 'agent':
            start_agent()
        elif args.component == 'elasticsearch':
            sys.stdout.write('[+] Starting ElasticSearch.\n')
            started = elasticsearch.ElasticProcess().start(stdout=True)
            if started:
                sys.stdout.write('[+] ElasticSearch started successfully. Check its status at any time with: '
                                 '\'dynamite.py status elasticsearch\'.\n')
            else:
                sys.stdout.write('[-] An error occurred while attempting to start ElasticSearch.\n')
        elif args.component == 'logstash':
            sys.stdout.write('[+] Starting LogStash\n')
            started = logstash.LogstashProcess().start(stdout=True)
            if started:
                sys.stdout.write('[+] LogStash started successfully. Check its status at any time with: '
                                 '\'dynamite.py status logstash\'.\n')
            else:
                sys.stdout.write('[-] An error occurred while attempting to start LogStash.\n')
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'status':
        if args.component == 'agent':
            status_agent()
        elif args.component == 'elasticsearch':
            sys.stdout.write(json.dumps(elasticsearch.ElasticProcess().status(), indent=1) + '\n')
        elif args.component == 'logstash':
            sys.stdout.write(json.dumps(logstash.LogstashProcess().status(), indent=1) + '\n')
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'stop':
        if args.component == 'agent':
            stop_agent()
        elif args.component == 'elasticsearch':
            sys.stdout.write('[+] Stopping ElasticSearch.\n')
            stopped = elasticsearch.ElasticProcess().stop(stdout=True)
            if stopped:
                sys.stdout.write('[+] ElasticSearch stopped successfully.\n')
            else:
                sys.stdout.write('[-] An error occurred while attempting to stop ElasticSearch.\n')
        elif args.component == 'logstash':
            sys.stdout.write('[+] Stopping LogStash.\n')
            stopped = logstash.LogstashProcess().stop(stdout=True)
            if stopped:
                sys.stdout.write('[+] LogStash stopped successfully.\n')
            else:
                sys.stdout.write('[-] An error occurred while attempting to stop LogStash.\n')
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'restart':
        if args.component == 'agent':
            stop_agent()
            start_agent()
        elif args.component == 'elasticsearch':
            sys.stdout.write('[+] Restarting ElasticSearch.\n')
            restarted = elasticsearch.ElasticProcess().restart(stdout=True)
            if restarted:
                sys.stdout.write('[+] ElasticSearch restarted successfully.\n')
            else:
                sys.stdout.write('[-] An error occurred while attempting to start ElasticSearch.\n')
        elif args.component == 'logstash':
            sys.stdout.write('[+] Restarting LogStash.\n')
            restarted = logstash.LogstashProcess().restart(stdout=True)
            if restarted:
                sys.stdout.write('[+] LogStash restarted successfully.\n')
            else:
                sys.stdout.write('[-] An error occurred while attempting to start LogStash.\n')
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'profile':
        if args.component == 'elasticsearch':
            sys.stdout.write('[+] Profiling ElasticSearch.\n')
            es_profiler = elasticsearch.ElasticProfiler(stderr=True)
            sys.stdout.write(str(es_profiler) + '\n')
            sys.exit(0)
        elif args.component == 'agent':
            sys.stdout.write('[+] Profiling Agent.\n')
            pf_ring_profiler = pf_ring.PFRingProfiler()
            sys.stdout.write(str(pf_ring_profiler) + '\n')
            sys.exit(0)
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    else:
        sys.stderr.write('[-] Unrecognized command - {}\n'.format(args.command))
        sys.exit(1)
