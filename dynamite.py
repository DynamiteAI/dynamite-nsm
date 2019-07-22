import sys
import json
import argparse
import traceback

from lib import agent
from lib import monitor
from lib import utilities
from lib.services import elasticsearch, kibana, logstash


def _parse_cmdline():
    parser = argparse.ArgumentParser(
        description='Install/Configure the Dynamite Analysis Framework.'
    )
    parser.add_argument('command', metavar='command', type=str,
                        help='An action to perform [prepare|install|start|stop|status]')
    parser.add_argument('component', metavar='component', type=str,
                        help='The component to perform an action against [agent|logstash|elasticsearch]')
    parser.add_argument('--interface', type=str, dest='network_interface', required='install' in sys.argv
                                                                            and 'agent' in sys.argv,
                        help='A network interface to analyze traffic on.')
    parser.add_argument('--host', type=str, dest='host', required=('point' in sys.argv)
                                                                  or ('install' in sys.argv and 'agent' in sys.argv)
                                                                  or (not elasticsearch.ElasticProfiler().is_installed
                                                                      and 'install' in sys.argv and 'kibana' in sys.argv
                                                                      ),
                        help='A valid Ipv4/Ipv6 address or hostname')
    parser.add_argument('--agent-label', type=str, dest='agent_label', required='install' in sys.argv and 'agent' in
                                                                                sys.argv,
                        help='A descriptive label associated with the agent. '
                             'This could be a location on your network (VLAN01),'
                             'or the types of servers on a segment (E.G Workstations-US-1).')
    parser.add_argument('--port', type=int, dest='port', required=('point' in sys.argv)
                                                                  or ('install' in sys.argv and 'agent' in sys.argv)
                                                                  or (not elasticsearch.ElasticProfiler().is_installed
                                                                      and 'install' in sys.argv and 'kibana' in sys.argv)

                        , help='A valid port [1-65535]')
    parser.add_argument('--debug', default=False, dest='debug', action='store_true',
                        help='Include detailed error messages in console.')
    return parser.parse_args()


def _fatal_exception(action, component, debug=False):
    message = '[-] {}.{} failed. Is it installed?\n' \
              '[-] \'dynamite.py install {}\'\n'.format(action, component, component)
    sys.stderr.write(message)
    if debug:
        sys.stderr.write('\n\n========== DEBUG ==========\n\n')
        traceback.print_exc(file=sys.stderr)
    sys.exit(1)

def _not_installed(action, component):
    _fatal_exception(action, component, debug=False)


if __name__ == '__main__':
    if not utilities.is_root():
        sys.stderr.write('[-] This script must be run as root.\n')
        sys.exit(1)
    utilities.create_dynamite_root_directory()
    args = _parse_cmdline()
    if args.command == 'point':
        if args.component == 'agent':
            agent.point_agent(args.host, args.port)
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'prepare':
        if args.component == 'agent':
            agent.prepare_agent()
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'install':
        if args.component == 'elasticsearch':
            if elasticsearch.install_elasticsearch(stdout=True, create_dynamite_user=True, install_jdk=True):
                sys.exit(0)
            else:
                sys.stderr.write('[-] Failed to install ElasticSearch.\n')
                sys.exit(1)
        elif args.component == 'logstash':
            if logstash.install_logstash(stdout=True, create_dynamite_user=True, install_jdk=True):
                sys.exit(0)
            else:
                sys.stderr.write('[-] Failed to install Logstash.\n')
                sys.exit(1)
        elif args.component == 'kibana':
            if not elasticsearch.ElasticProfiler().is_installed:
                if kibana.install_kibana(stdout=True, create_dynamite_user=True, install_jdk=True):
                    sys.exit(0)
                else:
                    sys.stderr.write('[-] Failed to install Kibana.\n')
                    sys.exit(1)
            else:
                if kibana.install_kibana(elasticsearch_host=args.host, elasticsearch_port=args.port,
                                         stdout=True, create_dynamite_user=True, install_jdk=True):
                    sys.exit(0)
                else:
                    sys.stderr.write('[-] Failed to install Kibana.\n')
                    sys.exit(1)
        elif args.component == 'agent':
            agent.install_agent(agent_label=args.agent_label, network_interface=args.network_interface,
                                logstash_target='{}:{}'.format(args.host, args.port))
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'start':
        if args.component == 'elasticsearch':
            try:
                sys.stdout.write('[+] Starting ElasticSearch.\n')
                started = elasticsearch.ElasticProcess().start(stdout=True)
                if started:
                    sys.stdout.write('[+] ElasticSearch started successfully. Check its status at any time with: '
                                     '\'dynamite.py status elasticsearch\'.\n')
                    sys.exit(0)
                elif not elasticsearch.ElasticProfiler(stderr=False).is_installed:
                    _not_installed('start', 'elasticsearch')
                    sys.exit(0)
                else:
                    sys.stdout.write('[-] An error occurred while attempting to start ElasticSearch.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('start', 'elasticsearch', args.debug)
        elif args.component == 'logstash':
            try:
                sys.stdout.write('[+] Starting LogStash\n')
                started = logstash.LogstashProcess().start(stdout=True)
                if started:
                    sys.stdout.write('[+] LogStash started successfully. Check its status at any time with: '
                                     '\'dynamite.py status logstash\'.\n')
                    sys.exit(0)
                elif not logstash.LogstashProfiler(stderr=False).is_installed:
                    _not_installed('start', 'logstash')
                    sys.exit(0)
                else:
                    sys.stderr.write('[-] An error occurred while attempting to start LogStash.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('start', 'logstash', args.debug)
        elif args.component == 'kibana':
            try:
                sys.stdout.write('[+] Starting Kibana\n')
                started = kibana.KibanaProcess().start(stdout=True)
                if started:
                    sys.stdout.write('[+] Kibana started successfully. Check its status at any time with: '
                                     '\'dynamite.py status kibana\'.\n')
                    sys.exit(0)
                elif not kibana.KibanaProfiler(stderr=False).is_installed:
                    _not_installed('start', 'kibana')
                    sys.exit(0)
                else:
                    sys.stderr.write('[-] An error occurred while attempting to start Kibana.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('start', 'kibana', args.debug)
        elif args.component == 'monitor':
            try:
                if agent.start_agent():
                    sys.exit(0)
                else:
                    sys.stderr.write('[-] Failed to start monitor.')
                    sys.exit(1)
            except Exception:
                _fatal_exception('start', 'monitor', args.debug)
        elif args.component == 'agent':
            try:
                if agent.start_agent():
                    sys.exit(0)
                else:
                    sys.stderr.write('[-] Failed to start agent.')
                    sys.exit(1)
            except Exception:
                _fatal_exception('start', 'agent', args.debug)
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'status':
            if args.component == 'elasticsearch':
                if not elasticsearch.ElasticProfiler(stderr=False).is_installed:
                    _not_installed('start', 'elasticsearch')
                    sys.exit(0)
                try:
                    sys.stdout.write(json.dumps(elasticsearch.ElasticProcess().status(), indent=1) + '\n')
                    sys.exit(0)
                except Exception:
                    _fatal_exception('status', 'elasticsearch', args.debug)
            elif args.component == 'logstash':
                if not logstash.LogstashProfiler(stderr=False).is_installed:
                    _not_installed('status', 'elasticsearch')
                    sys.exit(0)
                try:
                    sys.stdout.write(json.dumps(logstash.LogstashProcess().status(), indent=1) + '\n')
                except Exception:
                    _fatal_exception('status', 'logstash', args.debug)
            elif args.component == 'kibana':
                if not kibana.KibanaProfiler(stderr=False).is_installed:
                    _not_installed('status', 'kibana')
                    sys.exit(0)
                try:
                    sys.stdout.write(json.dumps(kibana.KibanaProcess().status(), indent=1) + '\n')
                except Exception:
                    _fatal_exception('status', 'kibana', args.debug)
            elif args.component == 'monitor':
                try:
                    es_status, ls_status, kb_status = monitor.status_monitor()
                    sys.stdout.write(json.dumps(dict(
                        ElasticSearch=es_status,
                        LogStash=ls_status,
                        Kibana=kb_status
                    ), indent=1))
                    sys.stdout.flush()
                    sys.exit(0)
                except Exception:
                    _fatal_exception('status', 'monitor', args.debug)
            elif args.component == 'agent':
                try:
                    zeek_status, other_processes = agent.status_agent()
                    sys.stdout.write(zeek_status)
                    sys.stdout.write(json.dumps(other_processes, indent=1))
                    sys.stdout.flush()
                    sys.exit(0)
                except Exception:
                    _fatal_exception('status', 'agent', args.debug)
            else:
                sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
                sys.exit(1)
    elif args.command == 'stop':
        if args.component == 'elasticsearch':
            try:
                sys.stdout.write('[+] Stopping ElasticSearch.\n')
                stopped = elasticsearch.ElasticProcess().stop(stdout=True)
                if not elasticsearch.ElasticProfiler(stderr=False).is_installed:
                    _not_installed('stop', 'kibana')
                    sys.exit(0)
                elif stopped:
                    sys.stdout.write('[+] ElasticSearch stopped successfully.\n')
                    sys.exit(0)
                else:
                    sys.stdout.write('[-] An error occurred while attempting to stop ElasticSearch.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('stop', 'elasticsearch', args.debug)
        elif args.component == 'logstash':
            try:
                sys.stdout.write('[+] Stopping LogStash.\n')
                stopped = logstash.LogstashProcess().stop(stdout=True)
                if not logstash.LogstashProfiler(stderr=False).is_installed:
                    _not_installed('stop', 'logstash')
                    sys.exit(0)
                elif stopped:
                    sys.stdout.write('[+] LogStash stopped successfully.\n')
                    sys.exit(0)
                else:
                    sys.stdout.write('[-] An error occurred while attempting to stop LogStash.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('stop', 'logstash', args.debug)
        elif args.component == 'kibana':
            try:
                sys.stdout.write('[+] Stopping Kibana.\n')
                stopped = kibana.KibanaProcess().stop(stdout=True)
                if not kibana.KibanaProfiler(stderr=False).is_installed:
                    _not_installed('stop', 'kibana')
                    sys.exit(0)
                elif stopped:
                    sys.stdout.write('[+] Kibana stopped successfully.\n')
                    sys.exit(0)
                else:
                    sys.stdout.write('[-] An error occurred while attempting to stop Kibana.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('stop', 'kibana', args.debug)
        elif args.component == 'monitor':
            try:
                if monitor.stop_monitor():
                    sys.exit(0)
                else:
                    sys.stderr.write('[-] Failed to stop monitor.')
            except Exception:
                _fatal_exception('stop', 'monitor', args.debug)
        elif args.component == 'agent':
            try:
                if agent.stop_agent():
                    sys.exit(0)
                else:
                    sys.stderr.write('[-] Failed to stop agent.')
            except Exception:
                _fatal_exception('stop', 'agent', args.debug)
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'restart':
        if args.component == 'elasticsearch':
            try:
                sys.stdout.write('[+] Restarting ElasticSearch.\n')
                restarted = elasticsearch.ElasticProcess().restart(stdout=True)
                if not elasticsearch.ElasticProfiler(stderr=False).is_installed:
                    _not_installed('restart', 'kibana')
                    sys.exit(0)
                elif restarted:
                    sys.stdout.write('[+] ElasticSearch restarted successfully.\n')
                    sys.exit(0)
                else:
                    sys.stdout.write('[-] An error occurred while attempting to start ElasticSearch.\n')
                    sys.exit(0)
            except Exception:
                _fatal_exception('restart', 'elasticsearch', args.debug)
        elif args.component == 'logstash':
            try:
                sys.stdout.write('[+] Restarting LogStash.\n')
                restarted = logstash.LogstashProcess().restart(stdout=True)
                if not logstash.LogstashProfiler(stderr=False).is_installed:
                    _not_installed('restart', 'logstash')
                    sys.exit(0)
                elif restarted:
                    sys.stdout.write('[+] LogStash restarted successfully.\n')
                    sys.exit(0)
                else:
                    sys.stdout.write('[-] An error occurred while attempting to start LogStash.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('restart', 'logstash', args.debug)
        elif args.component == 'kibana':
            try:
                sys.stdout.write('[+] Restarting Kibana.\n')
                restarted = kibana.KibanaProcess().restart(stdout=True)
                if not kibana.KibanaProfiler(stderr=False).is_installed:
                    _not_installed('restart', 'logstash')
                    sys.exit(0)
                elif restarted:
                    sys.stdout.write('[+] Kibana restarted successfully.\n')
                    sys.exit(0)
                else:
                    sys.stdout.write('[-] An error occurred while attempting to start Kibana.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('restart', 'kibana', args.debug)
        elif args.component == 'monitor':
            try:
                if monitor.stop_monitor():
                    if agent.start_agent():
                        sys.stdout.write('[+] Monitor restarted successfully.\n')
                        sys.exit(0)
                    else:
                        sys.stdout.write('[-] Monitor failed to start.\n')
                        sys.exit(1)
                else:
                    sys.stdout.write('[-] Monitor failed to stop.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('restart', 'monitor', args.debug)
        elif args.component == 'agent':
            try:
                if agent.stop_agent():
                    if agent.start_agent():
                        sys.stdout.write('[+] Agent restarted successfully.\n')
                        sys.exit(0)
                    else:
                        sys.stdout.write('[-] Agent failed to start.\n')
                        sys.exit(1)
                else:
                    sys.stdout.write('[-] Agent failed to stop.\n')
                    sys.exit(1)
            except Exception:
                _fatal_exception('restart', 'agent', args.debug)
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'profile':
        if args.component == 'elasticsearch':
            try:
                sys.stdout.write('[+] Profiling ElasticSearch.\n')
                profile_result = elasticsearch.ElasticProfiler(stderr=True)
                sys.stdout.write('[+]  ELASTICSEARCH.INSTALLED: {}\n'.format(profile_result.is_installed))
                sys.stdout.write('[+] ELASTICSEARCH.CONFIGURED: {}\n'.format(profile_result.is_configured))
                sys.stdout.write('[+]    ELASTICSEARCH.RUNNING: {}\n'.format(profile_result.is_running))
                sys.stdout.write('[+]     ELASTICSEARCH.API_UP: {}\n'.format(profile_result.is_listening))
                sys.exit(0)
            except Exception:
                _fatal_exception('profile', 'elasticsearch', args.debug)
        elif args.component == 'logstash':
            try:
                sys.stdout.write('[+] Profiling LogStash.\n')
                profile_result = logstash.LogstashProfiler(stderr=True)
                sys.stdout.write('[+]            LOGSTASH.INSTALLED: {}\n'.format(profile_result.is_installed))
                sys.stdout.write('[+]  LOGSTASH.ELASIFLOW.INSTALLED: {}\n'.format(profile_result.is_installed))
                sys.stdout.write('[+]           LOGSTASH.CONFIGURED: {}\n'.format(profile_result.is_configured))
                sys.stdout.write('[+]              LOGSTASH.RUNNING: {}\n'.format(profile_result.is_running))
                sys.exit(0)
            except Exception:
                _fatal_exception('profile', 'elasticsearch', args.debug)
        elif args.component == 'kibana':
            try:
                sys.stdout.write('[+] Profiling Kibana.\n')
                profile_result = kibana.KibanaProfiler(stderr=True)
                sys.stdout.write('[+]  KIBANA.INSTALLED: {}\n'.format(profile_result.is_installed))
                sys.stdout.write('[+] KIBANA.CONFIGURED: {}\n'.format(profile_result.is_configured))
                sys.stdout.write('[+]    KIBANA.RUNNING: {}\n'.format(profile_result.is_running))
                sys.stdout.write('[+]     KIBANA.API_UP: {}\n'.format(profile_result.is_listening))
                sys.exit(0)
            except Exception:
                _fatal_exception('profile', 'kibana', args.debug)
        elif args.component == 'agent':
            try:
                profile_result = agent.profile_agent()
                sys.stdout.write('[+]  PF_RING.INSTALLED: {}\n'.format(profile_result['PF_RING']['INSTALLED']))
                sys.stdout.write('[+]    PF_RING.RUNNING: {}\n'.format(profile_result['PF_RING']['RUNNING']))
                sys.stdout.write('[+]     ZEEK.INSTALLED: {}\n'.format(profile_result['ZEEK']['INSTALLED']))
                sys.stdout.write('[+]       ZEEK.RUNNING: {}\n'.format(profile_result['ZEEK']['RUNNING']))
                sys.stdout.write('[+] FILEBEAT.INSTALLED: {}\n'.format(profile_result['FILEBEAT']['INSTALLED']))
                sys.stdout.write('[+]   FILEBEAT.RUNNING: {}\n'.format(profile_result['FILEBEAT']['RUNNING']))
                sys.stdout.flush()
            except Exception:
                _fatal_exception('profile', 'agent', args.debug)
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    else:
        sys.stderr.write('[-] Unrecognized command - {}\n'.format(args.command))
        sys.exit(1)
