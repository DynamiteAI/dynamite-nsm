from dynamite_nsm.cmd.kibana.uninstall import interface as kibana_uninstaller_interface

if __name__ == '__main__':
    parser = kibana_uninstaller_interface.get_parser()
    args = parser.parse_args()
    kibana_uninstaller_interface.execute(args)
