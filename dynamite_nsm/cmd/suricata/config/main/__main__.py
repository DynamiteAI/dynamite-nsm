from dynamite_nsm.cmd.suricata.config.main import interface as suricata_rules_interface

if __name__ == '__main__':
    parser = suricata_rules_interface.get_parser()
    args = parser.parse_args()
    
    print(suricata_rules_interface.execute(args))
