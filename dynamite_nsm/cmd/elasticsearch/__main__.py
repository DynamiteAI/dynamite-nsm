from dynamite_nsm.cmd.elasticsearch import install, process, uninstall, config
from dynamite_nsm.cmd.elasticsearch import get_action_parser
from dynamite_nsm.services.elasticsearch import process as process_service

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    interface = None
    result = None
    try:
        if args.sub_interface == 'install':
            interface = install.interface
            interface.execute(args)
        elif args.sub_interface == 'uninstall':
            interface = uninstall.interface
            interface.execute(args)
        elif args.sub_interface == 'process':
            result = process.interface.execute(args)
            if result:
                if args.action != 'status':
                    print(process_service.status(stdout=args.stdout, pretty_print_status=args.pretty_print_status,
                                                 verbose=args.verbose))
                else:
                    print(result)
        else:
            if args.sub_interface == 'config':
                config.get_action_parser().print_help()
            elif args.sub_interface == 'java':
                print(config.java.interface.execute(args))
            elif args.sub_interface == 'main':
                print(config.main.interface.execute(args))
    except AttributeError:
        parser.print_help()