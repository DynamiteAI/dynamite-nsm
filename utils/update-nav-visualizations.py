import json
proto = 'SSH'
link = '#/dashboard/c66577a0-babb-11e9-9323-33f42755b777'
path = '/Users/jaminbecker/PycharmProjects/dynamite-nsm/utils/saved_object_templates/elastiflow.kibana.api.7.2.X.ndjson'


def sort_app_protocols(markdown):
    found = False
    event_links = ''
    app_links = ''
    for line in markdown.split('\n'):
        if 'Application Protocols' in line:
            found = True
            continue
        if found:
            app_links += line.strip()
        else:
            event_links += line + '\n'
    app_tokenized = app_links.replace(' ', '').split('|')
    highlighted_token = None
    for token in app_tokenized:
        if '**' in token:
            highlighted_token = token.split(']')[0].split('[')[1].replace('**', '')
    sorted_app_tokenized = sorted(app_links.replace(' ', '').replace('**', '').split('|'))
    for i in range(0, len(sorted_app_tokenized)):
        if str(highlighted_token) in sorted_app_tokenized[i]:
            sorted_app_tokenized[i] = sorted_app_tokenized[i].replace(highlighted_token,
                                                                      '**{}**'.format(highlighted_token))
    return event_links + 'Application Protocols\n\n' + ' | '.join(sorted_app_tokenized)


for line in open(path, 'r').readlines():
    saved_obj = json.loads(line)
    title = saved_obj['attributes'].get('title', '')
    if 'Dynamite: NAV' in title:
        obj_vis_state = json.loads(saved_obj['attributes']['visState'])
        markdown = obj_vis_state['params']['markdown']
        if 'Application Protocols' in markdown:
            new_markdown = sort_app_protocols(markdown + ' | [{}]({})'.format(proto, link))
            obj_vis_state['params']['markdown'] = new_markdown
            saved_obj['attributes']['visState'] = json.dumps(obj_vis_state)
            line = json.dumps(saved_obj)
    print(line)
