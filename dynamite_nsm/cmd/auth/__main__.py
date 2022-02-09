from dynamite_nsm.cmd import process_arguments
from dynamite_nsm.cmd.auth import get_action_parser

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    res = process_arguments(args, component='remotes', interface=args.interface,
                            sub_interface=args.sub_interface)

    if res:
        print(res)
