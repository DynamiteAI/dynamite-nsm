from dynamite_nsm.cmd.logstash.config.java import interface as logstash_java_config_interface

if __name__ == '__main__':
    parser = logstash_java_config_interface.get_parser()
    args = parser.parse_args()
    print(logstash_java_config_interface.execute(args))