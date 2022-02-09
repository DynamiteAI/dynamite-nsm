from dynamite_nsm.cmd.auth.uninstall import interface as remotes_uninstaller_interface

if __name__ == '__main__':
    parser = remotes_uninstaller_interface.get_parser()
    args = parser.parse_args()
    remotes_uninstaller_interface.execute(args)
