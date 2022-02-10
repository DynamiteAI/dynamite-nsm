from dynamite_nsm.cmd.zeek.config.node import interface as zeek_config_interface

if __name__ == '__main__':
    parser = zeek_config_interface.get_parser()
    args = parser.parse_args()

    print(zeek_config_interface.execute(args))