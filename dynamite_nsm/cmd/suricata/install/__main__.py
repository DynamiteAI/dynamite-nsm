from dynamite_nsm.cmd.suricata.install import interface as suricata_installer_interface

if __name__ == '__main__':
    parser = suricata_installer_interface.get_parser()
    args = parser.parse_args()
    suricata_installer_interface.execute(args)
