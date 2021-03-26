from dynamite_nsm.cmd import process_arguments
from dynamite_nsm.cmd.kibana import get_action_parser
from dynamite_nsm.cmd.kibana.config import get_action_parser as get_config_action_parser

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    res = None
    try:
        res = process_arguments(args, component='kibana', interface=args.interface,
                                sub_interface=args.sub_interface)
    except AttributeError:
        try:
            if args.interface == 'config':
                get_config_action_parser().print_help()
            else:
                try:
                    res = process_arguments(args, component='kibana', interface=args.interface)
                except AttributeError:
                    parser.print_help()
        except AttributeError:
            parser.print_help()
    if res:
        print(res)

