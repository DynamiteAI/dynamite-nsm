from dynamite_nsm.cmd import process_arguments, get_dynamite_parser

if __name__ == '__main__':
    parser = get_dynamite_parser()
    args = parser.parse_args()
    res = None
    print(args)
    try:
        try:
            res = process_arguments(args, component=args.component, interface=args.interface,
                                    sub_interface=args.sub_interface)
        except AttributeError as e:
            print(e)
            res = process_arguments(args, component=args.component, interface=args.interface)
    except AttributeError:
        parser.print_help()
    if res:
        print(res)
