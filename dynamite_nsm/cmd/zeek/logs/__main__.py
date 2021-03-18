from dynamite_nsm.cmd.zeek.logs import get_action_parser
from dynamite_nsm.cmd.zeek.logs import cluster, broker, metrics, reporter

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    try:
        if args.sub_menu == 'broker':
            broker.interface.execute(args)
        elif args.sub_menu == 'cluster':
            cluster.interface.execute(args)
        elif args.sub_menu == 'metrics':
            metrics.interface.execute(args)
        elif args.sub_menu == 'reporter':
            reporter.interface.execute(args)
        else:
            parser.print_help()
    except AttributeError:
        parser.print_help()
