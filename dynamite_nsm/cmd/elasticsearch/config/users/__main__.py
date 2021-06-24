from dynamite_nsm.cmd.elasticsearch.config.users import interface as elasticsearch_users_interface

if __name__ == '__main__':
    parser = elasticsearch_users_interface.get_parser()
    args = parser.parse_args()
    print(elasticsearch_users_interface.execute(args))
