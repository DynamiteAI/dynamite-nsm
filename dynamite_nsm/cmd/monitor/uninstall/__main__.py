from dynamite_nsm.cmd.monitor.uninstall import interface as monitor_uninstaller_interface

if __name__ == '__main__':
    parser = monitor_uninstaller_interface.get_parser()
    args = parser.parse_args()
    monitor_uninstaller_interface.execute(args)
