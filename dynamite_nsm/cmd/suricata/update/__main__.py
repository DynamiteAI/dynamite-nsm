from dynamite_nsm.cmd.suricata.update import interface as suricata_rules_updater_interface

if __name__ == '__main__':
    parser = suricata_rules_updater_interface.get_parser()
    args = parser.parse_args()
    suricata_rules_updater_interface.execute(args)
