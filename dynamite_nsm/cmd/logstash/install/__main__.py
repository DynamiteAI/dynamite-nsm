from dynamite_nsm.cmd.logstash.install import interface as logstash_installer_interface

if __name__ == '__main__':
    parser = logstash_installer_interface.get_parser()
    args = parser.parse_args()
    logstash_installer_interface.execute(args)
