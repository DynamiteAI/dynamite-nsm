import sys
import json
import argparse

from lib import agent
from lib import pf_ring
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


if __name__ == '__main__':
    args = _parse_cmdline()
    if not utilities.is_root():
        sys.stderr.write('[-] This script must be run as root.\n')
        sys.exit(1)
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
            elasticsearch.install_elasticsearch()
        elif args.component == 'logstash':
            logstash.install_logstash()
        elif args.component == 'agent':
            agent.install_agent()
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'start':
        if args.component == 'agent':
            agent.start_agent()
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
            agent.status_agent()
        elif args.component == 'elasticsearch':
            sys.stdout.write(json.dumps(elasticsearch.ElasticProcess().status(), indent=1) + '\n')
        elif args.component == 'logstash':
            sys.stdout.write(json.dumps(logstash.LogstashProcess().status(), indent=1) + '\n')
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    elif args.command == 'stop':
        if args.component == 'agent':
            agent.stop_agent()
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
            agent.stop_agent()
            agent.start_agent()
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
        else:
            sys.stderr.write('[-] Unrecognized component - {}\n'.format(args.component))
            sys.exit(1)
    else:
        sys.stderr.write('[-] Unrecognized command - {}\n'.format(args.command))
        sys.exit(1)
