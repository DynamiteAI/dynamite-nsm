from dynamite_nsm.cmd.filebeat.uninstall import interface as filebeat_uninstaller_interface

if __name__ == '__main__':
    parser = filebeat_uninstaller_interface.get_parser()
    args = parser.parse_args()
    filebeat_uninstaller_interface.execute(args)
