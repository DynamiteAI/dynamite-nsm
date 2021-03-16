from dynamite_nsm.commandline.utilities.suricata.logs import get_action_parser
from dynamite_nsm.commandline.utilities.suricata.logs import main, metrics

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    try:
        if args.sub_interface == 'main':
            main.interface.execute(args)
        elif args.sub_interface == 'metrics':
            metrics.interface.execute(args)
    except AttributeError:
        parser.print_help()
