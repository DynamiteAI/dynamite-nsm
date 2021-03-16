from dynamite_nsm.services.zeek import process as process_service
from dynamite_nsm.cmd.zeek import install, process
from dynamite_nsm.cmd.zeek import get_action_parser
from dynamite_nsm.cmd.zeek.logs import cluster, broker, metrics, reporter

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    try:
        if args.sub_interface == 'install':
            install.interface.execute(args)
        elif args.sub_interface == 'process':
            result = process.interface.execute(args)
            if result:
                if args.action != 'status':
                    print(process_service.status(stdout=args.stdout, pretty_print_status=args.pretty_print_status,
                                                 verbose=args.verbose))
                else:
                    print(result)
        else:
            if args.sub_interface == 'broker':
                broker.interface.execute(args)
            elif args.sub_interface == 'cluster':
                cluster.interface.execute(args)
            elif args.sub_interface == 'reporter':
                reporter.interface.execute(args)
            else:
                metrics.interface.execute(args)
    except AttributeError:
        parser.print_help()