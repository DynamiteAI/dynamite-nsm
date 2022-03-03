import re


ipv4_address_pattern = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1'
                                  '[0-9]{2}|2[0-4][0-9]|25[0-5])$')
ipv4_cidr_pattern = re.compile(f'^{ipv4_address_pattern.pattern[1:-1]}/((?:[0-9])|(?:[1-2][0-9])|(?:3[0-2]))$')

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

ipv6_cidr_pattern = re.compile(
    f'^{ipv6_address_pattern.pattern[1:-1]}/((?:[0-9])|(?:[1-9][0-9])|(?:10[0-9])|(?:11[0-9])|(?:12[0-8]))$')


def validate_suricata_address_group_values(s):
    """Determine if a string is a valid Suricata address group
    Must be like the following:
        ! 1.1.1.1                       (Every IP address but 1.1.1.1)
        ![1.1.1.1, 1.1.1.2]             (Every IP address but 1.1.1.1 and 1.1.1.2)
        $HOME_NET                       (Your setting of HOME_NET in yaml)
        [$EXTERNAL_NET, !$HOME_NET]     (EXTERNAL_NET and not HOME_NET)
        [10.0.0.0/24, !10.0.0.5]        (10.0.0.0/24 except for 10.0.0.5)
    Args:
        s: Test String
    Returns:
         True if meets the suricata_address_group_value conditions
    """

    def validate_token(token):
        if str(token).startswith('!'):
            token = token[1:]

        def token_is_cidr(tok):
            if '/' in tok:
                # Not a valid IP/CIDR pair
                try:
                    ip, prefix = tok.split('/')
                except ValueError:
                    return False
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
                              '$SMTP_SERVERS', '$MODBUS_SERVER', '$MODBUS_CLIENT', '$ENIP_CLIENT', '$ENIP_SERVER']
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
    """Determine if a string is a valid Suricata address group
    Must be like the following:
        [80, 81, 82]    (port 80, 81 and 82)
        [80: 82]        (Range from 80 till 82)
        [1024: ]        (From 1024 till the highest port-number)
        !80             (Every port but 80)
        [80:100,!99]    (Range from 80 till 100 but 99 excluded)
        [1:80,![2,4]]

    Args:
        s: Test String
    Returns:
         True if meets the suricata_address_group_value conditions
    """

    def validate_token(token):

        if str(token).startswith('!'):
            token = token[1:]

        def token_is_port(tok):
            tok = str(tok)
            try:
                int(tok)
                if int(tok) < 0 or int(tok) > 65535:
                    return False
            except ValueError:
                return False
            return '.' not in str(tok)

        def token_is_range(tok):
            tok = str(tok)
            if ':' in str(tok):
                port_range = tok.split(':')
                port_range = [p for p in port_range if p.strip()]
                if len(port_range) == 1:
                    tok = port_range[0]
                    return token_is_port(tok)
                elif len(port_range) == 2:
                    r1, r2 = port_range
                    return token_is_port(r1) and token_is_port(r2) and int(r1) < int(r2)

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

        return token_is_range(token) or token_is_port(token) or token_is_list(token)

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
            # Check if 'any' is in the list (you can't combine any with other values)
            elif 'any' == t:
                return False
        return True
    else:
        if 'any' == s:
            return True
        return validate_token(s) or s in valid_var_subs