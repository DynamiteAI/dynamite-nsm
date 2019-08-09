import json
proto = 'SSH'
link = '#/dashboard/c66577a0-babb-11e9-9323-33f42755b777'
path = '/Users/jaminbecker/PycharmProjects/dynamite-nsm/utils/saved_object_templates/elastiflow.kibana.api.7.2.X.ndjson'

for line in open(path, 'r').readlines():
    saved_obj = json.loads(line)
    title = saved_obj['attributes'].get('title', '')
    if 'Dynamite: NAV' in title:
        obj_vis_state = json.loads(saved_obj['attributes']['visState'])
        markdown = obj_vis_state['params']['markdown']
        if 'Application Protocols' in markdown:
            new_markdown = markdown + ' | [{}]({})'.format(proto, link)
            obj_vis_state['params']['markdown'] = new_markdown
            saved_obj['attributes']['visState'] = json.dumps(obj_vis_state)
            line = json.dumps(saved_obj)
    print(line.strip())