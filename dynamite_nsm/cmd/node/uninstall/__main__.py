from dynamite_nsm.cmd.node.uninstall import interface as node_uninstaller_interface

if __name__ == '__main__':
    parser = node_uninstaller_interface.get_parser()
    args = parser.parse_args()
    node_uninstaller_interface.execute(args)
