from dynamite_nsm.cmd.zeek.reset.site import interface as zeek_reset_interface

if __name__ == '__main__':
    parser = zeek_reset_interface.get_parser()
    args = parser.parse_args()
    zeek_reset_interface.execute(args)
