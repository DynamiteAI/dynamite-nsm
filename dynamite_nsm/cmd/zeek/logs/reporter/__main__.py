from dynamite_nsm.cmd.zeek.logs.reporter import interface

if __name__ == '__main__':
    parser = interface.get_parser()
    args = parser.parse_args()
    interface.execute(args)
