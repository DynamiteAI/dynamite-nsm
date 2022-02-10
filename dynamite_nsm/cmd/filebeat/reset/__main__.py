from dynamite_nsm.cmd.filebeat.reset import interface as filebeat_reset_interface

if __name__ == '__main__':
    parser = filebeat_reset_interface.get_parser()
    args = parser.parse_args()
    filebeat_reset_interface.execute(args)
