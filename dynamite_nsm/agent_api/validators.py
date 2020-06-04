import re

ipv4_address_pattern = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1'
                                  '[0-9]{2}|2[0-4][0-9]|25[0-5])$')

ipv6_address_pattern = re.compile('^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]'
                                  '|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]'
                                  '{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:'
                                  '[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.)'
                                  '{3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::'
                                  '(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]'
                                  '|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25'
                                  '[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:'
                                  '[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]'
                                  '|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:'
                                  '[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]'
                                  '{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.)'
                                  '{3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:)'
                                  '{,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|'
                                  '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|'
                                  '1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::'
                                  '(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]'
                                  '|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:'
                                  '[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:)'
                                  '{,6}[0-9A-Fa-f]{1,4})?::)$')


def validate_name(s):
    """
    Must be between 5 and 30 characters and
        - contain only alphanumeric and hyphen/underscore characters,
        - and start and end with alphanumeric characters

    :param s: Test string
    :return: True, if meets name conditions
    """
    return bool(5 <= len(s) <= 30 and re.search(r'^[a-zA-Z0-9]([\w -]*[a-zA-Z0-9]$)', s))


def validate_suricata_address_group_name(s):
    """
    Must be one of the valid Suricata address groups

    :param s: Test string
    :return: True, if meets the suricata_address_group_name conditions
    """
    return s in ['home_net', 'external_net', 'http_servers', 'sql_servers', 'dns_servers', 'telnet_servers',
                 'aim_servers', 'dc_servers', 'modbus_server', 'modbus_client', 'enip_client', 'enip_server'
                 ]


def validate_suricata_address_group_values(s):
    """

    Must be like the following:
        ! 1.1.1.1                       (Every IP address but 1.1.1.1)
        ![1.1.1.1, 1.1.1.2]             (Every IP address but 1.1.1.1 and 1.1.1.2)
        $HOME_NET                       (Your setting of HOME_NET in yaml)
        [$EXTERNAL_NET, !$HOME_NET]     (EXTERNAL_NET and not HOME_NET)
        [10.0.0.0/24, !10.0.0.5]        (10.0.0.0/24 except for 10.0.0.5)

    :param s: Test String
    :return: True if meets the suricata_address_group_value conditions
    """

    def validate_token(token):

        # Check for CIDR notation
        if '/' in token:
            ip, prefix = token.split('/')
            # Check for invalid prefix
            if int(prefix) < 0 or int(prefix) > 128:
                return False
        else:
            ip = token
        if ip in valid_var_subs:
            return True
        elif ipv4_address_pattern.findall(ip) or ipv6_address_pattern.findall(ip):
            return True
        elif ip.startswith('!') and ipv4_address_pattern.findall(ip[1:]) \
                or ipv6_address_pattern.findall(ip[1:]):
            return True
        return False

    valid_group_value_vars = ['$HOME_NET', '$EXTERNAL_NET', '$HTTP_SERVERS', '$SQL_SERVERS',
                              '$DNS_SERVERS', '$TELNET_SERVERS', '$AIM_SERVERS', '$DC_SERVERS',
                              '$MODBUS_SERVER', '$MODBUS_CLIENT', '$ENIP_CLIENT', '$ENIP_SERVER']
    valid_neg_group_value_vars = ['!' + g for g in valid_group_value_vars]

    valid_var_subs = valid_group_value_vars + valid_neg_group_value_vars

    # List Formatting
    if '[' in s and ']' in s:

        # Negation is valid against sets as well (E.G ![ $HOME_NET, 192.168.0.0/24])
        if s.startswith('!'):
            s = s.replace(' ', '')[1:]
        tokenized_list = s.replace(' ', '')[1:-1].split(',')
        for t in tokenized_list:
            # Check if token in string is valid variable substitution, IP, or CIDR
            if t not in valid_var_subs and not validate_token(t):
                return False
            # Check if 'any' is in the list (you can't combine any with other values)
            elif 'any' == t:
                return False
        return True
    # String formatting
    else:
        if 'any' == s:
            return True
        # Check if string is valid variable substitution, IP, or CIDR
        return validate_token(s) and s not in valid_var_subs


def test_validate_suricata_address_groups():
    valid_test_expressions = [
        'any',
        '8.8.8.8',
        '!8.8.8.8',
        '192.168.0.1/32',
        '!192.168.0.1/32',
        '[1.1.1.1, 1.1.1.2]',
        '[1.1.1.1, !1.1.1.2]',
        '![1.1.1.1, 1.1.1.2]',
        '2001:0002:6c::430',
        '!2001:0002:6c::430',
        'ff01:0:0:0:0:0:0:2',
        '!ff01:0:0:0:0:0:0:2',
        'fe80::200:5aee:feaa:20a2',
        '2000::/3',
        '!2000::/3',
        'ff00::/8',
        '!ff00::/8',
        '2001:0002::/48',
        '!2001:0002::/48',
        '::/128',
        '::1/128',
        '[$EXTERNAL_NET]',
        '![$EXTERNAL_NET]',
        '[!$EXTERNAL_NET]',
        '[$EXTERNAL_NET, !$HOME_NET]',
        '![$EXTERNAL_NET, !$HOME_NET]',
        '[$EXTERNAL_NET, !$HOME_NET, $MODBUS_CLIENT, $HTTP_SERVERS]',
        '[$EXTERNAL_NET, !$HOME_NET, $MODBUS_CLIENT, $HTTP_SERVERS, 192.168.0.1, 8.8.8.8]',
        '[$EXTERNAL_NET, !$HOME_NET, $MODBUS_CLIENT, $HTTP_SERVERS, 192.168.0.1, 8.8.8.8, ff01:0:0:0:0:0:0:2, ::/128]'
    ]

    invalid_test_expressions = [
        'badstring',
        '!any',
        '![any]',
        '192.168.1',
        '2002:cb0a:3cdd:1:',
        '::1/129',
        '[$HOME_NET, any]'

    ]

    for expr in valid_test_expressions + invalid_test_expressions:
        print(expr, validate_suricata_address_group_values(expr))
