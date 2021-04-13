from dynamite_nsm.cmd.filebeat.config.main import interface as filebeat_config_interface

if __name__ == '__main__':
    parser = filebeat_config_interface.get_parser()
    args = parser.parse_args()
    print(filebeat_config_interface.execute(args))