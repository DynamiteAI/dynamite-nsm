from dynamite_nsm.cmd.filebeat.install import interface as filebeat_installer_interface

if __name__ == '__main__':
    parser = filebeat_installer_interface.get_parser()
    args = parser.parse_args()
    filebeat_installer_interface.execute(args)
