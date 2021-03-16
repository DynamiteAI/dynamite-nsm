from dynamite_nsm.cmd.zeek.uninstall import interface as zeek_uninstaller_interface

if __name__ == '__main__':
    parser = zeek_uninstaller_interface.get_parser()
    args = parser.parse_args()
    zeek_uninstaller_interface.execute(args)
