from dynamite_nsm.cmd.zeek import get_action_parser
from dynamite_nsm.cmd.zeek.logs import cluster, broker, metrics, reporter

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    try:
        if args.sub_interface == 'broker':
            broker.interface.execute(args)
        elif args.sub_interface == 'cluster':
            cluster.interface.execute(args)
        elif args.sub_interface == 'metrics':
            metrics.interface.execute(args)
        elif args.sub_interface == 'reporter':
            reporter.interface.execute(args)
    except AttributeError:
        parser.print_help()
