from dynamite_nsm.cmd.kibana.install import interface as kibana_installer_interface

if __name__ == '__main__':
    parser = kibana_installer_interface.get_parser()
    args = parser.parse_args()
    kibana_installer_interface.execute(args)
