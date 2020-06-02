from zlib import adler32
from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.zeek import config as zeek_config

api = Namespace(
    name='Zeek Scripts',
    description='Enable/Disable Zeek Scripts.',
)

env_vars = utilities.get_environment_file_dict()
ZEEK_SCRIPT_DIRECTORY = env_vars.get('ZEEK_SCRIPTS')


@api.route('/', endpoint='scripts-config')
class ZeekScriptConfig(Resource):

    @staticmethod
    def hash_and_id_scripts(enabled_scripts, disabled_scripts):
        # Hashing algo isn't perfect could possibly have collisions, but we're programmers not
        # mathematicians the chances of this happening are relatively low.
        script_count = len(enabled_scripts) + len(disabled_scripts)

        return dict(
            enabled=sorted([{"id": adler32(str(name).encode("utf-8")) % (script_count ** 3), "name": name} for name in
                            enabled_scripts], key=lambda i: i['id']),
            disabled=sorted([{"id": adler32(str(name).encode("utf-8")) % (script_count ** 3), "name": name} for name in
                             disabled_scripts], key=lambda i: i['id'])
        )

    def get(self):
        script_config = zeek_config.ScriptConfigManager(configuration_directory=ZEEK_SCRIPT_DIRECTORY)
        scripts_and_ids = self.hash_and_id_scripts(script_config.list_enabled_scripts(),
                                                   script_config.list_disabled_scripts())
        return scripts_and_ids, 200


@api.route('/<script_id>', endpoint='script-manager')
class ZeekScriptManager(Resource):

    def get(self, script_id):
        script_config = zeek_config.ScriptConfigManager(configuration_directory=ZEEK_SCRIPT_DIRECTORY)
        scripts_and_ids = ZeekScriptConfig.hash_and_id_scripts(script_config.list_enabled_scripts(),
                                                               script_config.list_disabled_scripts())
        enabled_scripts = [str(script['id']) for script in scripts_and_ids['enabled']]
        disabled_scripts = [str(script['id']) for script in scripts_and_ids['disabled']]

        if script_id in enabled_scripts:
            idx = enabled_scripts.index(script_id)
            scripts_and_ids['enabled'][idx].update({'status': 'enabled'})
            return scripts_and_ids['enabled'][idx], 200
        elif script_id in disabled_scripts:
            idx = disabled_scripts.index(script_id)
            scripts_and_ids['disabled'][idx].update({'status': 'disabled'})
            return scripts_and_ids['disabled'][idx], 200
        else:
            return dict(message='Could not find script {}'.format(script_id)), 404

    def put(self, script_id):
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument(
            'status', dest='status',
            location='json', required=True, type=str, choices=['enabled', 'disabled', 'enable', 'disable'],
            help='Enable/Disable a script.'
        )
        args = arg_parser.parse_args()

        script_config = zeek_config.ScriptConfigManager(configuration_directory=ZEEK_SCRIPT_DIRECTORY)
        scripts_and_ids = ZeekScriptConfig.hash_and_id_scripts(script_config.list_enabled_scripts(),
                                                               script_config.list_disabled_scripts())
        enabled_scripts = [str(script['id']) for script in scripts_and_ids['enabled']]
        disabled_scripts = [str(script['id']) for script in scripts_and_ids['disabled']]

        if script_id in enabled_scripts:
            idx = enabled_scripts.index(script_id)
            script_name = scripts_and_ids['enabled'][idx]['name']
        elif script_id in disabled_scripts:
            idx = disabled_scripts.index(script_id)
            script_name = scripts_and_ids['disabled'][idx]['name']
        else:
            script_name = None
            return dict(message='Could not find script {}'.format(script_id)), 404

        if args.status == 'enabled' or args.status == 'enable':
            script_config.enable_script(script_name)
            action = 'enabled'
        else:
            script_config.disable_script(script_name)
            action = 'disabled'
        try:
            script_config.write_config()
        except zeek_config.zeek_exceptions.WriteZeekConfigError as e:
            return dict(message=str(e)), 500
        return dict(message='Script {} ({}) {}.'.format(script_id, script_name, action)), 200
