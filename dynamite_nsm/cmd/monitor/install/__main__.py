from dynamite_nsm.cmd.monitor.install import interface as monitor_installer_interface

if __name__ == '__main__':
    parser = monitor_installer_interface.get_parser()
    args = parser.parse_args()
    monitor_installer_interface.execute(args)
