from dynamite_nsm.cmd.elasticsearch.config.java import interface as elasticsearch_java_config_interface

if __name__ == '__main__':
    parser = elasticsearch_java_config_interface.get_parser()
    args = parser.parse_args()
    print(elasticsearch_java_config_interface.execute(args))