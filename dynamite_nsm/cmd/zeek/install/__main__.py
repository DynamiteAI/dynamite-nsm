from dynamite_nsm.cmd.zeek.install import interface as zeek_installer_interface

if __name__ == '__main__':
    parser = zeek_installer_interface.get_parser()
    args = parser.parse_args()
    zeek_installer_interface.execute(args)
