from dynamite_nsm.cmd.suricata.reset import interface as suricata_reset_interface

if __name__ == '__main__':
    parser = suricata_reset_interface.get_parser()
    args = parser.parse_args()
    suricata_reset_interface.execute(args)
