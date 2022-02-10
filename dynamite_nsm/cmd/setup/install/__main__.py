from dynamite_nsm.cmd.setup.install import interface as setup_installer_interface

if __name__ == '__main__':
    parser = setup_installer_interface.get_parser()
    args = parser.parse_args()
    setup_installer_interface.execute(args)
