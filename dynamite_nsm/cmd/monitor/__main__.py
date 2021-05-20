from dynamite_nsm.cmd import process_arguments
from dynamite_nsm.cmd.updates import get_action_parser

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    res = None
    try:
        res = process_arguments(args, component='monitor', interface=args.interface)
    except AttributeError:
        parser.print_help()
    if res:
        print(res)
