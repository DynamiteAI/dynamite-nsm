from dynamite_nsm.cmd.node.install import interface as node_installer_interface

if __name__ == '__main__':
    parser = node_installer_interface.get_parser()
    args = parser.parse_args()
    node_installer_interface.execute(args)
