from dynamite_nsm.cmd.updates.install import interface as updates_installer_interface

if __name__ == '__main__':
    parser = updates_installer_interface.get_parser()
    args = parser.parse_args()
    updates_installer_interface.execute(args)
