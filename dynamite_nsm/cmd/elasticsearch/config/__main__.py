from dynamite_nsm.cmd import process_arguments
from dynamite_nsm.cmd.elasticsearch.config import get_action_parser

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    res = None
    try:
        res = process_arguments(args, component='elasticsearch', interface='config',
                                sub_interface=args.sub_interface)
    except AttributeError:
        parser.print_help()
    if res:
        print(res)

