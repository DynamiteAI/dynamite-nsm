from dynamite_nsm.commandline.utilities.kibana import get_action_parser
from dynamite_nsm.commandline.utilities.kibana import install, process

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    try:
        if args.sub_interface == 'install':
            install.interface.execute(args)
        elif args.sub_interface == 'process':
            process.interface.execute(args)
    except AttributeError:
        parser.print_help()
