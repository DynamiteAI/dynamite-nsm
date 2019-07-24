import re
import time
import json


def _is_ip(field):
    IPV4SEG = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
    IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
    IPV6SEG = r'(?:(?:[0-9a-fA-F]){1,4})'
    IPV6GROUPS = (
        r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,
        r'(?:' + IPV6SEG + r':){1,7}:',
        r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,
        r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',
        r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',
        r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',
        r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',
        IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',
        r':(?:(?::' + IPV6SEG + r'){1,7}|:)',
        r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',
        r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,
        r'(?:' + IPV6SEG + r':){1,4}:[^\s:]' + IPV4ADDR,
    )
    IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])
    return re.match(IPV4ADDR, field) or re.match(IPV6ADDR, field)


def _is_numeric(field):
    try:
        float(field)
    except ValueError:
        return False
    return True


def identify_field_datatype(field):
    field = str(field)
    if field in ['true', 'false']:
        return 'boolean'
    elif _is_numeric(field):
        year = time.localtime(float(field)).tm_year
        if 1970 <= year <= 2262:
            return 'date'
        else:
            return 'float'
    elif _is_ip(field):
        return 'ip'
    elif _is_numeric(field):
            if '.' in field:
                return 'float'
            else:
                return 'long'
    else:
        try:
            res = json.loads(field, encoding='utf-8')
            if type(res) == dict:
                return 'object'
            elif type(res) == list:
                return 'nested'
            else:
                if len(field) < 50:
                    return 'keyword'
                else:
                    return 'text'
        except ValueError:
            if len(field) < 50:
                return 'keyword'
            else:
                return 'text'


def get_fields_and_types(ndjson_file):
    fields = {}
    logs = open(ndjson_file, 'r').read().split('\n')
    for log in logs:
        serialized_log = dict(json.loads(log))
        for field in sorted(serialized_log.keys()):
            if field not in fields.keys():
                fields[field] = identify_field_datatype(serialized_log[field])
        return fields


def create_index_template(name, ndjson_file):
    field_mappings = []
    for k, v in get_fields_and_types(ndjson_file).items():
        field_mappings.append(
            {
                'zeek.' + k: {
                    "mapping": {
                        "type": v
                    }
                }
            }
        )
    base_template = {
        'order': 0,
        'index-patterns': name,
        'mappings': {
            'dynamic_templates': field_mappings
        }
    }
    return base_template

print(json.dumps(create_index_template('ssh-events-*',
                                       '/Users/jaminbecker/PycharmProjects/dynamite-nsm/utils/log_samples/ssh.log.ndjson'
                                       ), indent=2))
