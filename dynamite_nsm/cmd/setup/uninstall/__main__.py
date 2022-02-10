from dynamite_nsm.cmd.setup.uninstall import interface as setup_uninstaller_interface

if __name__ == '__main__':
    parser = setup_uninstaller_interface.get_parser()
    args = parser.parse_args()
    setup_uninstaller_interface.execute(args)
