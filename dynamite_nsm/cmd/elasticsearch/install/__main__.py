from dynamite_nsm.cmd.elasticsearch.install import interface as elasticsearch_installer_interface

if __name__ == '__main__':
    parser = elasticsearch_installer_interface.get_parser()
    args = parser.parse_args()
    elasticsearch_installer_interface.execute(args)
