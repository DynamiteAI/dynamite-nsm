import re


def validate_name(s):
    """
    Must be between 5 and 30 characters and
        - contain only alphanumeric and hyphen/underscore characters,
        - and start and end with alphanumeric characters

    :param s: Test string
    :return: True, if meets name conditions
    """
    return bool(5 <= len(s) <= 30 and re.search(r'^[a-zA-Z0-9]([\w -]*[a-zA-Z0-9]$)', s))


'''
            home_net=suricata_instance_config.home_net,
            external_net=suricata_instance_config.external_net,
            http_servers=suricata_instance_config.http_servers,
            sql_servers=suricata_instance_config.sql_servers,
            dns_servers=suricata_instance_config.dns_servers,
            telnet_servers=suricata_instance_config.telnet_servers,
            aim_servers=suricata_instance_config.aim_servers,
            domain_controllers=suricata_instance_config.dc_servers,
            modbus_server=suricata_instance_config.modbus_server,
            modbud_client=suricata_instance_config.modbus_client,
            enip_client=suricata_instance_config.enip_client,
            enip_server=suricata_instance_config.enip_server
'''


def validate_suricata_address_group_name(s):
    return s in ['home_net', 'external_net', 'http_servers', 'sql_servers', 'dns_servers', 'telnet_servers',
                 'aim_servers', 'dc_servers', 'modbus_server', 'modbud_client', 'enip_client', 'enip_server'
                 ]
