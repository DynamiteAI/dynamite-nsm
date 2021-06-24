from dynamite_nsm.cmd.kibana.config.main import interface as kibana_config_interface

if __name__ == '__main__':
    parser = kibana_config_interface.get_parser()
    args = parser.parse_args()
    print(kibana_config_interface.execute(args))