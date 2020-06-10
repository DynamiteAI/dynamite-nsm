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


def validate_suricata_port_group_name(s):
    """
    Must be one of the valid Suricata port groups

    :param s: Test string
    :return: True, if meets the suricata_port_group_name conditions
    """
    return s in ['http_ports', 'shellcode_ports', 'oracle_ports', 'ssh_ports', 'dnp3_ports', 'modbus_ports',
                 'ftp_ports', 'file_data_ports'
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
        if str(token).startswith('!'):
            token = token[1:]

        def token_is_cidr(tok):
            if '/' in tok:
                ip, prefix = tok.split('/')
                # Check for invalid prefix
                try:
                    if int(prefix) < 0 or int(prefix) > 128:
                        return False
                except ValueError:
                    return False
            else:
                return False
            return True

        def token_is_ip(tok):
            return bool(ipv4_address_pattern.findall(tok) or ipv6_address_pattern.findall(tok))

        def token_is_list(tok):
            tok = str(tok)
            if '[' in tok and ']' in tok:
                # Negation is valid against sets as well (E.G ![ $HOME_NET, 192.168.0.0/24])
                if tok.startswith('!'):
                    tok = tok[1:]
                return validate_suricata_address_group_values(tok)
            return False

        return token_is_cidr(token) or token_is_ip(token) or token_is_list(token)

    s = str(s).replace(' ', '')
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

        # split on comma, but exclude values in square brackets
        tokenized_list = re.split(r",(?![^(\[]*[\])])", s[1:-1])
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
        return validate_token(s) or s in valid_var_subs


def validate_suricata_port_group_values(s):
    """

    Must be like the following:
        [80, 81, 82]    (port 80, 81 and 82)
        [80: 82]        (Range from 80 till 82)
        [1024: ]        (From 1024 till the highest port-number)
        !80             (Every port but 80)
        [80:100,!99]    (Range from 80 till 100 but 99 excluded)
        [1:80,![2,4]]

    :param s: Test String
    :return: True if meets the suricata_port_group_value conditions
    """

    def validate_token(token):

        if str(token).startswith('!'):
            token = token[1:]

        def token_is_int(tok):
            tok = str(tok)
            try:
                int(tok)
                if int(tok) < 1 or int(tok) > 65535:
                    return False
            except ValueError:
                return False
            return True
        if '.' in str(token):
            return False

        def token_is_range(tok):
            tok = str(tok)
            if ':' in str(tok):
                port_range = tok.split(':')
                if len(port_range) == 1:
                    tok = port_range[0]
                    return token_is_int(tok)
                elif len(port_range) == 2:
                    r1, r2 = port_range
                    return token_is_int(r1) and token_is_int(r2) and int(r1) < int(r2)

                else:
                    return False

        def token_is_list(tok):
            tok = str(tok)
            if '[' in tok and ']' in tok:

                # Negation is valid against sets as well (E.G ![ $HOME_NET, 192.168.0.0/24])
                if tok.startswith('!'):
                    tok = tok[1:]
                return validate_suricata_port_group_values(tok)
            return False

        return token_is_range(token) or token_is_int(token) or token_is_list(token)

    s = str(s).replace(' ', '')
    valid_group_value_vars = ['$HTTP_PORTS', '$SHELLCODE_PORTS', '$ORACLE_PORTS', '$SSH_PORTS',
                              '$DNP3_PORTS', '$MODBUS_PORTS', '$FILE_DATA_PORTS', '$FTP_PORTS']

    valid_neg_group_value_vars = ['!' + g for g in valid_group_value_vars]

    valid_var_subs = valid_group_value_vars + valid_neg_group_value_vars
    # List Formatting
    if '[' in s and ']' in s:
        # Negation is valid against sets as well (E.G ![ $HOME_NET, 192.168.0.0/24])
        if s.startswith('!'):
            s = s[1:]
            # split on comma, but exclude values in square brackets
        tokenized_list = re.split(r",(?![^(\[]*[\])])", s[1:-1])
        for t in tokenized_list:
            if t not in valid_var_subs and not validate_token(t):
                return False
        return True
    else:
        return validate_token(s) or s in valid_var_subs


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
        '$HOME_NET',
        '[$EXTERNAL_NET]',
        '![$EXTERNAL_NET]',
        '[!$EXTERNAL_NET]',
        '[$EXTERNAL_NET, !$HOME_NET]',
        '![$EXTERNAL_NET, !$HOME_NET]',
        '[$EXTERNAL_NET, !$HOME_NET, $MODBUS_CLIENT, $HTTP_SERVERS]',
        '[$EXTERNAL_NET, !$HOME_NET, $MODBUS_CLIENT, $HTTP_SERVERS, 192.168.0.1, 8.8.8.8]',
        '[$EXTERNAL_NET, !$HOME_NET, $MODBUS_CLIENT, $HTTP_SERVERS, 192.168.0.1, 8.8.8.8, ff01:0:0:0:0:0:0:2, ::/128]',
        '[192.168.0.1, 8.8.8.8, ff01:0:0:0:0:0:0:2, ::/128, 192.168.0.0/24, [192.168.0.1, 192.168.0.5, 192.168.0.5/32, $HTTP_SERVERS]]'
    ]

    invalid_test_expressions = [
        'badstring',
        '!any',
        '![any]',
        '192.168.1',
        '2002:cb0a:3cdd:1:',
        '::1/129',
        '[$HOME_NET, any]',
        ''
    ]

    for expr in valid_test_expressions + invalid_test_expressions:
        print(expr, validate_suricata_address_group_values(expr))


def test_validate_suricata_port_groups():
    valid_test_expressions = [
        80,
        '80',
        '!80',
        '[80, 8080, 8888]',
        '![80, 8080, 8888]',
        '$SHELLCODE_PORTS',
        '!$SHELLCODE_PORTS',
        '[$DNP3_PORTS, 8080, 8888]',
        '[$DNP3_PORTS, 8080, 8888]',
        '80:8000',
        '[80:440, !88, [80, 443]]'

    ]

    invalid_test_expressions = [
        'badstring',
        '!any',
        '![any]',
        '',
        0,
        5.5,
        '65536',
        ''
    ]

    for expr in valid_test_expressions + invalid_test_expressions:
        print(expr, validate_suricata_port_group_values(expr))

