from dynamite_nsm.commandline.utilities.logstash import get_action_parser
from dynamite_nsm.commandline.utilities.logstash import install

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    try:
        if args.sub_interface == 'install':
            install.interface.execute(args)
    except AttributeError:
        parser.print_help()
