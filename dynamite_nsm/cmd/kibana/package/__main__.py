from dynamite_nsm.cmd.kibana.package import interface as kibana_package_interface

if __name__ == '__main__':
    parser = kibana_package_interface.get_parser()
    args = parser.parse_args()
    kibana_package_interface.execute(args)