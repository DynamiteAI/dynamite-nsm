from dynamite_nsm.cmd.filebeat.logs import main, metrics
from dynamite_nsm.cmd.filebeat.logs import get_action_parser

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
