from dynamite_nsm.cmd.elasticsearch.uninstall import interface as elasticsearch_uninstaller_interface

if __name__ == '__main__':
    parser = elasticsearch_uninstaller_interface.get_parser()
    args = parser.parse_args()
    elasticsearch_uninstaller_interface.execute(args)
