from dynamite_nsm.commandline.utilities.elasticsearch.process import interface as elasticsearch_process_interface

if __name__ == '__main__':
    parser = elasticsearch_process_interface.get_parser()
    args = parser.parse_args()
    elasticsearch_process_interface.execute(args)
