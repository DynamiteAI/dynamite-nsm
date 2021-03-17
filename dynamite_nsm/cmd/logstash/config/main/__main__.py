from dynamite_nsm.cmd.logstash.config.main import interface as elasticsearch_config_interface

if __name__ == '__main__':
    parser = elasticsearch_config_interface.get_parser()
    args = parser.parse_args()
    print(elasticsearch_config_interface.execute(args))