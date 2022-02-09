from dynamite_nsm.cmd.auth.install import interface as remotes_installer_interface

if __name__ == '__main__':
    parser = remotes_installer_interface.get_parser()
    args = parser.parse_args()
    remotes_installer_interface.execute(args)
