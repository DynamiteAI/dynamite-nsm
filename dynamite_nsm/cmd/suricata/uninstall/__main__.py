from dynamite_nsm.cmd.suricata.uninstall import interface as suricata_uninstaller_interface

if __name__ == '__main__':
    parser = suricata_uninstaller_interface.get_parser()
    args = parser.parse_args()
    suricata_uninstaller_interface.execute(args)
