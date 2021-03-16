from dynamite_nsm.cmd.logstash.uninstall import interface as logstash_uninstaller_interface

if __name__ == '__main__':
    parser = logstash_uninstaller_interface.get_parser()
    args = parser.parse_args()
    logstash_uninstaller_interface.execute(args)
