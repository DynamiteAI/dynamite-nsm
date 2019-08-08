import sys
import json
from urllib2 import Request
from urllib2 import urlopen

object_types = [
    'config',
    'dashboard',
    'search',
    'visualization'
]
for object_type in object_types:
    data = {
        'type': object_type,
        'includeReferencesDeep': True
    }

    url_request = Request(
                        url='http://{}:{}/api/saved_objects/_export'.format(
                            sys.argv[1], sys.argv[2]
                        ),
                        data=json.dumps(data).encode('utf-8'),
                        headers={'Content-Type': 'application/json', 'kbn-xsrf': True}
                    )
    response = urlopen(url_request)
    print(response.read())