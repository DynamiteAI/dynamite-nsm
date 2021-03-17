from dynamite_nsm.cmd.logstash.config import main, java
from dynamite_nsm.cmd.logstash.config import get_action_parser

if __name__ == '__main__':
    parser = get_action_parser()
    args = parser.parse_args()
    try:
        if args.sub_interface == 'main':
            print(main.interface.execute(args))
        elif args.sub_interface == 'java':
            print(java.interface.execute(args))
    except AttributeError:
        parser.print_help()
